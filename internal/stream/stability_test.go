package stream

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"cencurity-engine/internal/detect"
	"cencurity-engine/internal/observability"
	"cencurity-engine/internal/policy"
	"cencurity-engine/internal/rules"
)

type failingWriter struct {
	header http.Header
	failAt int
	writes int
}

func (w *failingWriter) Header() http.Header { return w.header }
func (w *failingWriter) Write(payload []byte) (int, error) {
	w.writes++
	if w.writes >= w.failAt {
		return 0, errors.New("broken pipe")
	}
	return len(payload), nil
}
func (w *failingWriter) WriteHeader(_ int) {}
func (w *failingWriter) Flush()        {}

func newStabilityInterceptor(t *testing.T) *Interceptor {
	t.Helper()
	manager, err := rules.NewManager("", time.Hour, observability.NewLogger("error"))
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	return NewInterceptor(detect.NewScanner(manager), policy.NewEngine(manager), observability.NewLogger("error"), observability.NewMetrics())
}

// TestSSEReaderPartialEOF verifies that a partial final event still returns data.
func TestSSEReaderPartialEOF(t *testing.T) {
	reader := NewSSEReader(strings.NewReader("data: hello"))
	event, err := reader.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent() error = %v", err)
	}
	if event.Data != "hello" {
		t.Fatalf("unexpected data: %q", event.Data)
	}
}

// TestSSEReaderMalformedLine verifies malformed lines are ignored instead of crashing.
func TestSSEReaderMalformedLine(t *testing.T) {
	reader := NewSSEReader(strings.NewReader("wat\ndata: ok\n\n"))
	event, err := reader.ReadEvent()
	if err != nil {
		t.Fatalf("ReadEvent() error = %v", err)
	}
	if event.Data != "ok" {
		t.Fatalf("unexpected data: %q", event.Data)
	}
}

// TestInterceptorMalformedJSONPassThrough verifies fail-open passthrough for unknown JSON chunks.
func TestInterceptorMalformedJSONPassThrough(t *testing.T) {
	interceptor := newStabilityInterceptor(t)
	writer := newFlushRecorder()
	source := strings.NewReader("data: {not-json}\n\ndata: [DONE]\n\n")
	if err := interceptor.Stream(writer, source, func() {}, RequestMeta{RequestID: "r1", Vendor: "test", Model: "m1"}, observability.NewLogger("error")); err != nil {
		t.Fatalf("Stream() error = %v", err)
	}
	output := writer.buffer.String()
	if !strings.Contains(output, "data: {not-json}") {
		t.Fatalf("expected passthrough output, got %s", output)
	}
}

// TestInterceptorClientDisconnect verifies downstream write errors are returned cleanly.
func TestInterceptorClientDisconnect(t *testing.T) {
	interceptor := newStabilityInterceptor(t)
	writer := &failingWriter{header: make(http.Header), failAt: 1}
	source := strings.NewReader("data: {\"choices\":[{\"delta\":{\"content\":\"safe\"}}]}\n\n")
	if err := interceptor.Stream(writer, source, func() {}, RequestMeta{RequestID: "r1", Vendor: "test", Model: "m1"}, observability.NewLogger("error")); err == nil {
		t.Fatal("expected write error")
	}
}

// BenchmarkLongStreamPayload approximates long streamed payload overhead.
func BenchmarkLongStreamPayload(b *testing.B) {
	manager, err := rules.NewManager("", time.Hour, observability.NewLogger("error"))
	if err != nil {
		b.Fatalf("NewManager() error = %v", err)
	}
	interceptor := NewInterceptor(detect.NewScanner(manager), policy.NewEngine(manager), observability.NewLogger("error"), observability.NewMetrics())
	payload := bytes.Repeat([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"safe safe safe\"}}]}\n\n"), 2000)
	payload = append(payload, []byte("data: [DONE]\n\n")...)
	for index := 0; index < b.N; index++ {
		writer := newFlushRecorder()
		if err := interceptor.Stream(writer, bytes.NewReader(payload), func() {}, RequestMeta{RequestID: "bench", Vendor: "bench", Model: "bench"}, observability.NewLogger("error")); err != nil {
			b.Fatalf("Stream() error = %v", err)
		}
	}
}
