package stream

import (
	"strings"
	"testing"
	"time"

	"cencurity-engine/internal/detect"
	"cencurity-engine/internal/observability"
	"cencurity-engine/internal/policy"
	"cencurity-engine/internal/rules"
)

func benchmarkConcurrentStream(b *testing.B, parallelism int, payload string) {
	manager, err := rules.NewManager("", time.Hour, observability.NewLogger("error"))
	if err != nil {
		b.Fatalf("NewManager() error = %v", err)
	}
	interceptor := NewInterceptor(detect.NewScanner(manager), policy.NewEngine(manager), observability.NewLogger("error"), observability.NewMetrics())
	b.ReportAllocs()
	b.SetParallelism(parallelism)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			writer := newFlushRecorder()
			if err := interceptor.Stream(writer, strings.NewReader(payload), func() {}, RequestMeta{RequestID: "bench", Vendor: "bench", Model: "bench"}, observability.NewLogger("error")); err != nil {
				b.Fatalf("Stream() error = %v", err)
			}
		}
	})
}

func BenchmarkConcurrentStream10(b *testing.B) {
	payload := strings.Repeat("data: {\"choices\":[{\"delta\":{\"content\":\"safe\"}}]}\n\n", 100) + "data: [DONE]\n\n"
	benchmarkConcurrentStream(b, 10, payload)
}

func BenchmarkConcurrentStream50(b *testing.B) {
	payload := strings.Repeat("data: {\"choices\":[{\"delta\":{\"content\":\"safe\"}}]}\n\n", 100) + "data: [DONE]\n\n"
	benchmarkConcurrentStream(b, 50, payload)
}

func BenchmarkConcurrentStream100(b *testing.B) {
	payload := strings.Repeat("data: {\"choices\":[{\"delta\":{\"content\":\"safe\"}}]}\n\n", 100) + "data: [DONE]\n\n"
	benchmarkConcurrentStream(b, 100, payload)
}
