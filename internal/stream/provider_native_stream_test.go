package stream

import (
	"strings"
	"testing"

	"cencurity-engine/internal/observability"
)

func TestInterceptorRedactsClaudeNativeDelta(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	source := strings.NewReader(
		"event: content_block_delta\n" +
			"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"print(\\\"sk-1234567890abcdef\\\")\"}}\n\n" +
			"event: message_stop\n" +
			"data: {\"type\":\"message_stop\"}\n\n",
	)
	if err := interceptor.Stream(writer, source, func() {}, RequestMeta{RequestID: "claude-redact", Vendor: "anthropic", Model: "claude-sonnet-4-5"}, observability.NewLogger("error")); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	output := writer.buffer.String()
	if !strings.Contains(output, "event: content_block_delta") {
		t.Fatalf("expected anthropic event name to be preserved, got %s", output)
	}
	if !strings.Contains(output, "[REDACTED]") {
		t.Fatalf("expected redaction, got %s", output)
	}
	if !strings.Contains(output, "event: message_stop") {
		t.Fatalf("expected message_stop passthrough, got %s", output)
	}
}

func TestInterceptorBlocksClaudeNativeStream(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader(
		"event: content_block_delta\n" +
			"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"eval(\"}}\n\n",
	)
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "claude-block", Vendor: "anthropic", Model: "claude-sonnet-4-5"}, observability.NewLogger("error")); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	output := writer.buffer.String()
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(output, "event: error") || !strings.Contains(output, "permission_error") {
		t.Fatalf("expected anthropic error event, got %s", output)
	}
	if strings.Contains(output, "[DONE]") {
		t.Fatalf("did not expect OpenAI done marker, got %s", output)
	}
	if writer.flushes == 0 {
		t.Fatal("expected flushes during block flow")
	}
}

func TestInterceptorRedactsGeminiNativeStream(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	source := strings.NewReader(
		"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"print(\\\"AIzaSy1234567890abcdefghijklmn\\\")\"}]}}]}\n\n",
	)
	if err := interceptor.Stream(writer, source, func() {}, RequestMeta{RequestID: "gemini-redact", Vendor: "google", Model: "gemini-2.5-pro"}, observability.NewLogger("error")); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	output := writer.buffer.String()
	if !strings.Contains(output, "[REDACTED]") {
		t.Fatalf("expected redaction, got %s", output)
	}
	if !strings.Contains(output, "candidates") {
		t.Fatalf("expected gemini payload structure to be preserved, got %s", output)
	}
}

func TestInterceptorBlocksGeminiNativeStream(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader(
		"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"eval(\"}]}}]}\n\n",
	)
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "gemini-block", Vendor: "google", Model: "gemini-2.5-pro"}, observability.NewLogger("error")); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	output := writer.buffer.String()
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(output, "PERMISSION_DENIED") || !strings.Contains(output, "blocked by cencurity") {
		t.Fatalf("expected google-style error payload, got %s", output)
	}
	if strings.Contains(output, "[DONE]") {
		t.Fatalf("did not expect OpenAI done marker, got %s", output)
	}
	if writer.flushes == 0 {
		t.Fatal("expected flushes during block flow")
	}
}