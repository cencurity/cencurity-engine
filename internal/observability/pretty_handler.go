package observability

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"
)

type prettyHandler struct {
	writer     io.Writer
	options    *slog.HandlerOptions
	attrs      []slog.Attr
	groups     []string
	headerOnce *sync.Once
}

func newPrettyHandler(writer io.Writer, options *slog.HandlerOptions) slog.Handler {
	if options == nil {
		options = &slog.HandlerOptions{}
	}
	return &prettyHandler{
		writer:     writer,
		options:    options,
		headerOnce: &sync.Once{},
	}
}

func (h *prettyHandler) Enabled(_ context.Context, level slog.Level) bool {
	minimum := slog.LevelInfo
	if h.options != nil {
		minimum = h.options.Level.Level()
	}
	return level >= minimum
}

func (h *prettyHandler) Handle(ctx context.Context, record slog.Record) error {
	if !h.Enabled(ctx, record.Level) {
		return nil
	}

	fields := h.collectFields(record)
	if line, ok := h.formatPrettyLine(record, fields); ok {
		h.headerOnce.Do(func() {
			_, _ = fmt.Fprintln(h.writer, "TIME      MODEL              EVENT     DETAIL")
		})
		_, err := fmt.Fprintln(h.writer, line)
		return err
	}

	var fallback slog.Handler = slog.NewTextHandler(h.writer, h.options)
	if len(h.groups) > 0 {
		for _, group := range h.groups {
			fallback = fallback.WithGroup(group)
		}
	}
	if len(h.attrs) > 0 {
		fallback = fallback.WithAttrs(h.attrs)
	}
	return fallback.Handle(ctx, record)
}

func (h *prettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	combined := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	combined = append(combined, h.attrs...)
	combined = append(combined, attrs...)
	return &prettyHandler{
		writer:     h.writer,
		options:    h.options,
		attrs:      combined,
		groups:     append([]string(nil), h.groups...),
		headerOnce: h.headerOnce,
	}
}

func (h *prettyHandler) WithGroup(name string) slog.Handler {
	if strings.TrimSpace(name) == "" {
		return h
	}
	groups := append([]string(nil), h.groups...)
	groups = append(groups, name)
	return &prettyHandler{
		writer:     h.writer,
		options:    h.options,
		attrs:      append([]slog.Attr(nil), h.attrs...),
		groups:     groups,
		headerOnce: h.headerOnce,
	}
}

func (h *prettyHandler) collectFields(record slog.Record) map[string]string {
	fields := make(map[string]string, len(h.attrs)+8)
	for _, attr := range h.attrs {
		appendAttr(fields, attr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		appendAttr(fields, attr)
		return true
	})
	return fields
}

func appendAttr(fields map[string]string, attr slog.Attr) {
	attr.Value = attr.Value.Resolve()
	if attr.Equal(slog.Attr{}) {
		return
	}
	fields[attr.Key] = valueString(attr.Value)
}

func valueString(value slog.Value) string {
	switch value.Kind() {
	case slog.KindString:
		return value.String()
	case slog.KindTime:
		return value.Time().Format(time.RFC3339)
	default:
		return value.String()
	}
}

func (h *prettyHandler) formatPrettyLine(record slog.Record, fields map[string]string) (string, bool) {
	timestamp := record.Time.Format("15:04:05")
	model := trimTo(fields["vendor"]+"/"+fields["model"], 18)
	if model == "/" || model == "" {
		model = "system"
	}

	switch record.Message {
	case "rules_reloaded":
		return fmt.Sprintf("%-8s  %-18s %-9s %s", timestamp, "system", "RULES", fmt.Sprintf("%s rules from %s", emptyFallback(fields["count"], "0"), fields["path"])), true
	case "cast_server_starting":
		return fmt.Sprintf("%-8s  %-18s %-9s %s", timestamp, "system", "READY", fmt.Sprintf("listen %s -> %s", fields["listen_addr"], fields["upstream_url"])), true
	case "proxy_request_completed":
		action := strings.ToUpper(emptyFallback(fields["action"], "DONE"))
		detailParts := make([]string, 0, 2)
		if summary := actionSummary(fields); summary != "" {
			detailParts = append(detailParts, summary)
		}
		if rule := strings.TrimSpace(fields["matched_rule"]); rule != "" && rule != "none" {
			detailParts = append(detailParts, "rule "+rule)
		}
		return fmt.Sprintf("%-8s  %-18s %-9s %s", timestamp, model, action, strings.Join(detailParts, " | ")), true
	}

	return "", false
}

func humanize(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	replaced := strings.ReplaceAll(trimmed, "_", " ")
	return strings.TrimSpace(replaced)
}

func trimTo(value string, width int) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if len(trimmed) <= width {
		return trimmed
	}
	if width <= 1 {
		return trimmed[:width]
	}
	return trimmed[:width-1] + "…"
}

func emptyFallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func actionSummary(fields map[string]string) string {
	action := strings.ToLower(strings.TrimSpace(fields["action"]))
	context := strings.ToLower(strings.TrimSpace(fields["context"]))
	reason := strings.ToLower(strings.TrimSpace(fields["reason"]))

	switch action {
	case "allow":
		if context == "code_block" || context == "code" || context == "mixed" {
			return "safe code output"
		}
		return "safe output"
	case "redact":
		if reason != "" {
			return "sensitive content redacted"
		}
		return "content redacted"
	case "block":
		if reason != "" {
			return humanize(reason)
		}
		return "blocked by policy"
	default:
		parts := make([]string, 0, 2)
		if context != "" {
			parts = append(parts, humanize(context))
		}
		if reason != "" {
			parts = append(parts, humanize(reason))
		}
		return strings.Join(parts, " | ")
	}
}