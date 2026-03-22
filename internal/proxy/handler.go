package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"cencurity-engine/internal/observability"
	"cencurity-engine/internal/stream"
)

var requestSequence atomic.Uint64

// Handler proxies IDE requests to the configured LLM upstream.
type Handler struct {
	upstream    *Upstream
	interceptor *stream.Interceptor
	logger      *slog.Logger
	metrics     *observability.Metrics
}

// NewHandler creates a proxy handler bound to an upstream client.
func NewHandler(upstream *Upstream, interceptor *stream.Interceptor, logger *slog.Logger, metrics *observability.Metrics) *Handler {
	return &Handler{upstream: upstream, interceptor: interceptor, logger: logger, metrics: metrics}
}

// ServeHTTP forwards the request and streams the upstream response back.
func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	started := time.Now()
	h.metrics.IncRequestStarted()
	defer h.metrics.IncRequestCompleted()
	requestID := ensureRequestID(request)
	model := extractRequestModel(request)
	vendor := h.upstream.Vendor()
	requestLogger := h.logger.With(
		"request_id", requestID,
		"vendor", vendor,
		"model", model,
		"method", request.Method,
		"path", request.URL.Path,
	)
	writer.Header().Set("X-CAST-Request-ID", requestID)

	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	summary := &stream.RequestSummary{Action: "allow", MatchedRule: "none", Reason: "no_violation_detected", Context: "plain"}

	response, err := h.upstream.Do(request.Clone(ctx))
	if err != nil {
		h.metrics.IncUpstreamError()
		errorType := classifyError(err)
		h.metrics.IncErrorType(errorType)
		requestLogger.Error("upstream_request_failed", "error_type", errorType, "error", err.Error())
		http.Error(writer, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	defer func() {
		requestLogger.Info(
			"proxy_request_completed",
			"action", summary.Action,
			"matched_rule", summary.MatchedRule,
			"reason", summary.Reason,
			"context", summary.Context,
			"status", response.StatusCode,
			"latency_ms", time.Since(started).Milliseconds(),
		)
	}()

	copyResponseHeaders(writer.Header(), response.Header)
	if isSSE(response.Header) {
		h.metrics.IncSSERequest()
		writer.Header().Del("Content-Length")
	}
	writer.WriteHeader(response.StatusCode)

	if isSSE(response.Header) {
		if err := h.interceptor.Stream(writer, response.Body, cancel, stream.RequestMeta{RequestID: requestID, Vendor: vendor, Model: model, StartedAt: started, Summary: summary}, requestLogger); err != nil {
			errorType := classifyError(err)
			h.metrics.IncErrorType(errorType)
			requestLogger.Warn("stream_interception_failed", "error_type", errorType, "error", err.Error())
		}
		return
	}

	flusher, canFlush := writer.(http.Flusher)
	buffer := make([]byte, 32*1024)

	for {
		readBytes, readErr := response.Body.Read(buffer)
		if readBytes > 0 {
			if _, writeErr := writer.Write(buffer[:readBytes]); writeErr != nil {
				errorType := classifyError(writeErr)
				h.metrics.IncErrorType(errorType)
				requestLogger.Warn("downstream_write_failed", "error_type", errorType, "error", writeErr.Error())
				return
			}
			if canFlush {
				flusher.Flush()
			}
		}

		if readErr == nil {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			return
		}

		errorType := classifyError(readErr)
		h.metrics.IncErrorType(errorType)
		requestLogger.Warn("upstream_stream_read_failed", "error_type", errorType, "error", readErr.Error())
		return
	}
}

func ensureRequestID(request *http.Request) string {
	if value := strings.TrimSpace(request.Header.Get("X-Request-Id")); value != "" {
		return value
	}
	return fmt.Sprintf("cast-%d-%d", time.Now().UnixNano(), requestSequence.Add(1))
}

func extractRequestModel(request *http.Request) string {
	pathModel := extractModelFromPath(request.URL.Path)
	if request.Body == nil {
		if pathModel != "" {
			return pathModel
		}
		return "unknown"
	}
	payload, err := io.ReadAll(request.Body)
	if err != nil {
		request.Body = http.NoBody
		if pathModel != "" {
			return pathModel
		}
		return "unknown"
	}
	request.Body = io.NopCloser(strings.NewReader(string(payload)))
	if len(payload) == 0 {
		if pathModel != "" {
			return pathModel
		}
		return "unknown"
	}
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		if pathModel != "" {
			return pathModel
		}
		return "unknown"
	}
	if model, _ := body["model"].(string); strings.TrimSpace(model) != "" {
		return strings.TrimSpace(model)
	}
	if pathModel != "" {
		return pathModel
	}
	return "unknown"
}

func extractModelFromPath(requestPath string) string {
	trimmed := strings.Trim(requestPath, "/")
	if trimmed == "" {
		return ""
	}
	const marker = "/models/"
	index := strings.Index("/"+trimmed, marker)
	if index < 0 {
		return ""
	}
	modelPart := ("/" + trimmed)[index+len(marker):]
	if slash := strings.Index(modelPart, "/"); slash >= 0 {
		modelPart = modelPart[:slash]
	}
	if colon := strings.Index(modelPart, ":"); colon >= 0 {
		modelPart = modelPart[:colon]
	}
	return strings.TrimSpace(modelPart)
}

func classifyError(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.Canceled) {
		return "context_canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, io.EOF) {
		return "eof"
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "timeout"):
		return "timeout"
	case strings.Contains(message, "broken pipe") || strings.Contains(message, "connection reset"):
		return "client_disconnect"
	case strings.Contains(message, "context canceled"):
		return "context_canceled"
	default:
		return "io_error"
	}
}

func isSSE(header http.Header) bool {
	contentType := strings.ToLower(header.Get("Content-Type"))
	return strings.Contains(contentType, "text/event-stream")
}

func copyResponseHeaders(destination, source http.Header) {
	for key, values := range source {
		if isHopByHopHeader(key) {
			continue
		}
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}
