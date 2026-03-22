package stream

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"cencurity-engine/internal/detect"
	"cencurity-engine/internal/observability"
	"cencurity-engine/internal/policy"
	"cencurity-engine/internal/rules"
)

type flushRecorder struct {
	header     http.Header
	statusCode int
	buffer     bytes.Buffer
	flushes    int
}

func newFlushRecorder() *flushRecorder {
	return &flushRecorder{header: make(http.Header)}
}

func (r *flushRecorder) Header() http.Header { return r.header }
func (r *flushRecorder) Write(payload []byte) (int, error) { return r.buffer.Write(payload) }
func (r *flushRecorder) WriteHeader(statusCode int) { r.statusCode = statusCode }
func (r *flushRecorder) Flush() { r.flushes++ }

func newTestInterceptor(t *testing.T) *Interceptor {
	t.Helper()
	manager, err := rules.NewManager("", time.Hour, observability.NewLogger("error"))
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	return NewInterceptor(
		detect.NewScanner(manager),
		policy.NewEngine(manager),
		observability.NewLogger("error"),
		observability.NewMetrics(),
	)
}

// TestInterceptorRedacts verifies that redact modifies only streamed model text.
func TestInterceptorRedacts(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	source := strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"print(\\\"sk-1234567890abcdef\\\")\"}}]}\n\ndata: [DONE]\n\n")
	if err := interceptor.Stream(writer, source, func() {}, RequestMeta{RequestID: "test-redact", Vendor: "test", Model: "test-model"}, observability.NewLogger("error")); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	output := writer.buffer.String()
	if !strings.Contains(output, "[REDACTED]") {
		t.Fatalf("expected redaction, got %s", output)
	}
	if !strings.Contains(output, "data: [DONE]") {
		t.Fatal("expected done event")
	}
}

// TestInterceptorBlocks verifies block, cancel, and downstream termination.
func TestInterceptorBlocks(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"eval(\"}}]}\n\n")
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "test-block", Vendor: "test", Model: "test-model"}, observability.NewLogger("error")); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	output := writer.buffer.String()
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(output, ": blocked by cencurity") || !strings.Contains(output, "data: [DONE]") {
		t.Fatalf("unexpected block output: %s", output)
	}
	if writer.flushes == 0 {
		t.Fatal("expected flushes during block flow")
	}
}

// TestInterceptorBlocksSQLInjection verifies block enforcement for generated vulnerable code.
func TestInterceptorBlocksSQLInjection(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"db.Query(\\\"SELECT * FROM users WHERE id = \\\" + request.args[\\\"id\\\"])\"}}]}\n\n")
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "test-sqli-block", Vendor: "test", Model: "test-model"}, observability.NewLogger("error")); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	output := writer.buffer.String()
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(output, ": blocked by cencurity") {
		t.Fatalf("expected block output, got %s", output)
	}
	if !strings.Contains(output, "data: [DONE]") {
		t.Fatal("expected done event after block")
	}
}

// TestInterceptorBlocksAccumulatedSourceSink verifies CAST-style accumulated code analysis.
func TestInterceptorBlocksAccumulatedSourceSink(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader(
		"data: {\"choices\":[{\"delta\":{\"content\":\"```python\\nuser_id = request.args[\\\"id\\\"]\\n\"}}]}\n\n" +
			"data: {\"choices\":[{\"delta\":{\"content\":\"db.Query(\\\"SELECT * FROM users WHERE id = \\\" + user_id)\\n```\"}}]}\n\n",
	)
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "test-accumulated-sqli", Vendor: "test", Model: "test-model"}, observability.NewLogger("error")); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
		t.Fatalf("expected block output, got %s", writer.buffer.String())
	}
}

// TestInterceptorBlocksFrameworkSpecificXSS verifies framework-aware findings also enforce blocking.
func TestInterceptorBlocksFrameworkSpecificXSS(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	cancelled := false
	source := strings.NewReader(
		"data: {\"choices\":[{\"delta\":{\"content\":\"```tsx\\nimport React from 'react'\\nexport function Page({ searchParams }) {\\n\"}}]}\n\n" +
			"data: {\"choices\":[{\"delta\":{\"content\":\"return <div dangerouslySetInnerHTML={{ __html: searchParams.html }} />\\n}\\n```\"}}]}\n\n",
	)
	if err := interceptor.Stream(writer, source, func() { cancelled = true }, RequestMeta{RequestID: "test-react-xss", Vendor: "test", Model: "test-model"}, observability.NewLogger("error")); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if !cancelled {
		t.Fatal("expected cancel to be called")
	}
	if !strings.Contains(writer.buffer.String(), ": blocked by cencurity") {
		t.Fatalf("expected block output, got %s", writer.buffer.String())
	}
}

// TestInterceptorLongStream verifies stable pass-through for many safe chunks.
func TestInterceptorLongStream(t *testing.T) {
	interceptor := newTestInterceptor(t)
	writer := newFlushRecorder()
	var payload strings.Builder
	for index := 0; index < 200; index++ {
		payload.WriteString("data: {\"choices\":[{\"delta\":{\"content\":\"safe chunk ")
		payload.WriteString("x")
		payload.WriteString("\"}}]}\n\n")
	}
	payload.WriteString("data: [DONE]\n\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := interceptor.Stream(writer, strings.NewReader(payload.String()), cancel, RequestMeta{RequestID: "test-long", Vendor: "test", Model: "test-model"}, observability.NewLogger("error")); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	if !strings.Contains(writer.buffer.String(), "data: [DONE]") {
		t.Fatal("expected final done event")
	}
	select {
	case <-ctx.Done():
		t.Fatal("did not expect cancellation for safe stream")
	default:
	}
}

// BenchmarkInterceptorStream provides a basic throughput benchmark for long streams.
func BenchmarkInterceptorStream(b *testing.B) {
	manager, err := rules.NewManager("", time.Hour, observability.NewLogger("error"))
	if err != nil {
		b.Fatalf("NewManager() error = %v", err)
	}
	interceptor := NewInterceptor(detect.NewScanner(manager), policy.NewEngine(manager), observability.NewLogger("error"), observability.NewMetrics())
	payload := strings.Repeat("data: {\"choices\":[{\"delta\":{\"content\":\"safe\"}}]}\n\n", 100) + "data: [DONE]\n\n"
	for index := 0; index < b.N; index++ {
		writer := newFlushRecorder()
		if err := interceptor.Stream(writer, strings.NewReader(payload), func() {}, RequestMeta{RequestID: "bench", Vendor: "bench", Model: "bench"}, observability.NewLogger("error")); err != nil {
			b.Fatalf("Stream() error = %v", err)
		}
	}
}
