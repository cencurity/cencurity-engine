package stream

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"cencurity-engine/internal/detect"
	"cencurity-engine/internal/observability"
	"cencurity-engine/internal/policy"
)

const defaultWindowSize = 2048
const prefilterTailSize = 96

// Interceptor inspects model output text before forwarding it downstream.
type Interceptor struct {
	scanner *detect.Scanner
	analyzer *detect.CodeAnalyzer
	engine  *policy.Engine
	window  *Window
	code    *CodeBuffer
	context *ContextTracker
	logger  *slog.Logger
	metrics *observability.Metrics
}

// RequestMeta carries request-scoped logging fields into the stream pipeline.
type RequestMeta struct {
	RequestID string
	Vendor    string
	Model     string
	StartedAt time.Time
	Summary   *RequestSummary
}

type RequestSummary struct {
	Action      string
	MatchedRule string
	Reason      string
	Context     string
}

// NewInterceptor creates the MVP streaming inspection pipeline.
func NewInterceptor(scanner *detect.Scanner, engine *policy.Engine, logger *slog.Logger, metrics *observability.Metrics) *Interceptor {
	return &Interceptor{
		scanner: scanner,
		analyzer: detect.NewCodeAnalyzer(),
		engine:  engine,
		window:  NewWindow(defaultWindowSize),
		code:    NewCodeBuffer(defaultCodeBufferSize),
		context: &ContextTracker{},
		logger:  logger,
		metrics: metrics,
	}
}

// Stream reads SSE events, inspects model text, and forwards safe output.
func (i *Interceptor) Stream(writer http.ResponseWriter, source io.Reader, cancel context.CancelFunc, meta RequestMeta, logger *slog.Logger) error {
	reader := NewSSEReader(source)
	flusher, _ := writer.(http.Flusher)
	requestLogger := i.logger
	if logger != nil {
		requestLogger = logger
	}
	ensureSummary(meta.Summary)

	for {
		event, err := reader.ReadEvent()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			i.metrics.IncErrorType("sse_read_error")
			requestLogger.Warn("stream_read_failed", "error_type", "sse_read_error", "error", err.Error())
			return err
		}

		if event.Done {
			if _, err := writer.Write(event.Raw); err != nil {
				return err
			}
			flush(flusher)
			return nil
		}

		texts, err := extractTextValues(event.Data)
		if err != nil || len(texts) == 0 {
			if err != nil && err != io.EOF {
				i.metrics.IncErrorType("unparsed_json_chunk")
				requestLogger.Debug("stream_passthrough_event", "error_type", "unparsed_json_chunk", "reason", "unparsed_json_chunk", "error", err.Error())
			}
			if _, err := writer.Write(event.Raw); err != nil {
				i.metrics.IncErrorType("downstream_write_error")
				requestLogger.Warn("stream_write_failed", "error_type", "downstream_write_error", "error", err.Error())
				return err
			}
			flush(flusher)
			continue
		}

		decisionAction := policy.ActionAllow
		decisionRule := "none"
		decisionReason := "no_match"
		decisionContext := string(detect.ContentContextPlain)
		modified := false
		for _, text := range texts {
			if text == "" {
				continue
			}
			contextKind := i.context.Classify(text)
			codePrefix := i.code.ContextFor()
			shouldScan := i.scanner.ShouldScan(i.window.Tail(prefilterTailSize), text)
			shouldAnalyzeCode := codePrefix != "" && contextKind != detect.ContentContextPlain
			if !shouldScan && !shouldAnalyzeCode {
				setSummary(meta.Summary, policy.ActionAllow, "none", "no_violation_detected", string(contextKind))
				continue
			}

			prefix := i.window.ContextFor()
			var detections []detect.Detection
			if shouldScan {
				detections = i.scanner.Scan(prefix, text)
			}
			if shouldAnalyzeCode || contextKind != detect.ContentContextPlain {
				codeFindings := i.analyzer.AnalyzeCodeUnit(codePrefix+text, contextKind)
				detections = append(detections, detect.FindingsToDetections(codeFindings)...)
			}
			findings := detect.BuildFindings(detections, contextKind, text)
			bestFinding := detect.BestFinding(findings)
			for _, detection := range detections {
				i.metrics.IncDetection(detection.RuleID, detection.Category)
			}
			decision := i.engine.Decide(detections, contextKind)
			if actionRank(decision.Action) > actionRank(decisionAction) {
				decisionAction = decision.Action
				decisionRule = decision.RuleID
				decisionReason = decision.Reason
				decisionContext = string(contextKind)
			}

			switch decision.Action {
			case policy.ActionBlock:
				i.metrics.IncBlock()
				_ = bestFinding
				setSummary(meta.Summary, policy.ActionBlock, decision.RuleID, decision.Reason, string(contextKind))
				cancel()
				return writeBlockedStream(writer, flusher, meta)
			case policy.ActionRedact:
			case policy.ActionAllow:
				setSummary(meta.Summary, policy.ActionAllow, "none", "no_violation_detected", string(contextKind))
			}
		}

		if decisionAction == policy.ActionRedact {
			i.metrics.IncRedact()
			setSummary(meta.Summary, policy.ActionRedact, decisionRule, decisionReason, "mixed")
			payload, targets, err := extractTargets(event.Data)
			if err != nil || len(targets) == 0 {
				i.metrics.IncErrorType("redact_reparse_error")
				requestLogger.Warn("stream_passthrough_event", "error_type", "redact_reparse_error", "reason", "redact_reparse_error", "error", errString(err))
				if _, err := writer.Write(event.Raw); err != nil {
					i.metrics.IncErrorType("downstream_write_error")
					requestLogger.Warn("stream_write_failed", "error_type", "downstream_write_error", "error", err.Error())
					return err
				}
				flush(flusher)
				continue
			}
			for _, target := range targets {
				text := target.Text()
				if text == "" {
					continue
				}
				prefix := i.window.ContextFor()
				detections := i.scanner.Scan(prefix, text)
				redacted := policy.ApplyRedactions(text, detections)
				if redacted != text {
					target.Set(redacted)
					modified = true
				}
			}

			if !modified {
				if _, err := writer.Write(event.Raw); err != nil {
					i.metrics.IncErrorType("downstream_write_error")
					requestLogger.Warn("stream_write_failed", "error_type", "downstream_write_error", "error", err.Error())
					return err
				}
				flush(flusher)
				continue
			}

			encoded, err := json.Marshal(payload)
			if err != nil {
				i.metrics.IncErrorType("json_reencode_error")
				requestLogger.Warn("stream_encode_failed", "error_type", "json_reencode_error", "error", err.Error())
				return err
			}

			if _, err := writer.Write(event.EncodeWithData(string(encoded))); err != nil {
				i.metrics.IncErrorType("downstream_write_error")
				requestLogger.Warn("stream_write_failed", "error_type", "downstream_write_error", "error", err.Error())
				return err
			}
			for _, text := range texts {
				i.window.Add(text)
				i.context.Advance(text)
				i.code.Add(text, i.context.Classify(text))
			}
			flush(flusher)
			continue
		}

		if decisionAction == policy.ActionAllow {
			i.metrics.IncAllow()
			setSummary(meta.Summary, policy.ActionAllow, "none", "no_violation_detected", decisionContext)
		}

		for _, text := range texts {
			contextKind := i.context.Classify(text)
			i.window.Add(text)
			i.code.Add(text, contextKind)
			i.context.Advance(text)
		}

		if !modified {
			if _, err := writer.Write(event.Raw); err != nil {
				i.metrics.IncErrorType("downstream_write_error")
				requestLogger.Warn("stream_write_failed", "error_type", "downstream_write_error", "error", err.Error())
				return err
			}
			flush(flusher)
			continue
		}
	}
}

func ensureSummary(summary *RequestSummary) {
	if summary == nil {
		return
	}
	if summary.Action == "" {
		summary.Action = string(policy.ActionAllow)
		summary.MatchedRule = "none"
		summary.Reason = "no_violation_detected"
		summary.Context = string(detect.ContentContextPlain)
	}
}

func setSummary(summary *RequestSummary, action policy.Action, rule, reason, context string) {
	if summary == nil {
		return
	}
	if actionRank(action) < actionRank(policy.Action(summary.Action)) {
		return
	}
	summary.Action = string(action)
	summary.MatchedRule = rule
	summary.Reason = reason
	if strings.TrimSpace(context) == "" {
		summary.Context = string(detect.ContentContextPlain)
		return
	}
	summary.Context = context
}

type textTarget struct {
	mapParent   map[string]any
	mapKey      string
	sliceParent []any
	sliceIndex  int
}

func (t textTarget) Text() string {
	if t.mapParent != nil {
		value, _ := t.mapParent[t.mapKey].(string)
		return value
	}
	value, _ := t.sliceParent[t.sliceIndex].(string)
	return value
}

func (t textTarget) Set(value string) {
	if t.mapParent != nil {
		t.mapParent[t.mapKey] = value
		return
	}
	t.sliceParent[t.sliceIndex] = value
}

func extractTargets(raw string) (map[string]any, []textTarget, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil, io.EOF
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, nil, err
	}

	targets := make([]textTarget, 0, 4)
	appendOpenAITargets(payload, &targets)
	appendClaudeTargets(payload, &targets)
	appendGeminiTargets(payload, &targets)
	return payload, targets, nil
}

func appendOpenAITargets(payload map[string]any, targets *[]textTarget) {
	choices, _ := payload["choices"].([]any)
	for _, item := range choices {
		choice, ok := item.(map[string]any)
		if !ok {
			continue
		}
		appendMapStringTarget(choice, "text", targets)
		delta, _ := choice["delta"].(map[string]any)
		appendMapStringTarget(delta, "content", targets)
		contentParts, _ := delta["content"].([]any)
		for _, part := range contentParts {
			partMap, ok := part.(map[string]any)
			if !ok {
				continue
			}
			appendMapStringTarget(partMap, "text", targets)
		}
	}
}

func appendClaudeTargets(payload map[string]any, targets *[]textTarget) {
	appendMapStringTarget(payload, "completion", targets)
	if delta, _ := payload["delta"].(map[string]any); delta != nil {
		appendMapStringTarget(delta, "text", targets)
	}
	if contentBlock, _ := payload["content_block"].(map[string]any); contentBlock != nil {
		appendMapStringTarget(contentBlock, "text", targets)
	}
}

func appendGeminiTargets(payload map[string]any, targets *[]textTarget) {
	candidates, _ := payload["candidates"].([]any)
	for _, candidateItem := range candidates {
		candidate, ok := candidateItem.(map[string]any)
		if !ok {
			continue
		}
		content, _ := candidate["content"].(map[string]any)
		parts, _ := content["parts"].([]any)
		for _, partItem := range parts {
			part, ok := partItem.(map[string]any)
			if !ok {
				continue
			}
			appendMapStringTarget(part, "text", targets)
		}
	}
}

func appendMapStringTarget(parent map[string]any, key string, targets *[]textTarget) {
	if parent == nil {
		return
	}
	if _, ok := parent[key].(string); !ok {
		return
	}
	*targets = append(*targets, textTarget{mapParent: parent, mapKey: key})
}

func writeBlockedStream(writer http.ResponseWriter, flusher http.Flusher, meta RequestMeta) error {
	switch strings.ToLower(meta.Vendor) {
	case "anthropic":
		payload := map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "permission_error",
				"message": "blocked by cencurity",
			},
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if _, err := writer.Write([]byte("event: error\n")); err != nil {
			return err
		}
		if _, err := writer.Write([]byte("data: ")); err != nil {
			return err
		}
		if _, err := writer.Write(encoded); err != nil {
			return err
		}
		if _, err := writer.Write([]byte("\n\n")); err != nil {
			return err
		}
		flush(flusher)
		return nil
	case "google":
		payload := map[string]any{
			"error": map[string]any{
				"code":    7,
				"status":  "PERMISSION_DENIED",
				"message": "blocked by cencurity",
			},
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if _, err := writer.Write([]byte("data: ")); err != nil {
			return err
		}
		if _, err := writer.Write(encoded); err != nil {
			return err
		}
		if _, err := writer.Write([]byte("\n\n")); err != nil {
			return err
		}
		flush(flusher)
		return nil
	default:
		if _, err := writer.Write([]byte(": blocked by cencurity\n\n")); err != nil {
			return err
		}
		flush(flusher)
		if _, err := writer.Write([]byte("data: [DONE]\n\n")); err != nil {
			return err
		}
		flush(flusher)
		return nil
	}
}

func flush(flusher http.Flusher) {
	if flusher != nil {
		flusher.Flush()
	}
}

func actionRank(action policy.Action) int {
	switch action {
	case policy.ActionBlock:
		return 3
	case policy.ActionRedact:
		return 2
	default:
		return 1
	}
}

func errString(err error) string {
	if err == nil {
		return "unknown"
	}
	return err.Error()
}
