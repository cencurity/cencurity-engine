package observability

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Metrics stores lightweight in-memory counters for CAST runtime state.
type Metrics struct {
	requestsStarted   atomic.Uint64
	requestsCompleted atomic.Uint64
	sseRequests       atomic.Uint64
	allowActions      atomic.Uint64
	redactActions     atomic.Uint64
	blockActions      atomic.Uint64
	upstreamErrors    atomic.Uint64
	mu                sync.Mutex
	errorTypes        map[string]uint64
	detections        map[string]uint64
}

// NewMetrics creates a fresh metrics collector.
func NewMetrics() *Metrics {
	return &Metrics{
		errorTypes: make(map[string]uint64),
		detections: make(map[string]uint64),
	}
}

// IncRequestStarted increments the total request counter.
func (m *Metrics) IncRequestStarted() {
	m.requestsStarted.Add(1)
}

// IncRequestCompleted increments the completed request counter.
func (m *Metrics) IncRequestCompleted() {
	m.requestsCompleted.Add(1)
}

// IncSSERequest increments the intercepted SSE request counter.
func (m *Metrics) IncSSERequest() {
	m.sseRequests.Add(1)
}

// IncAllow increments the allow action counter.
func (m *Metrics) IncAllow() {
	m.allowActions.Add(1)
}

// IncRedact increments the redact action counter.
func (m *Metrics) IncRedact() {
	m.redactActions.Add(1)
}

// IncBlock increments the block action counter.
func (m *Metrics) IncBlock() {
	m.blockActions.Add(1)
}

// IncUpstreamError increments the upstream error counter.
func (m *Metrics) IncUpstreamError() {
	m.upstreamErrors.Add(1)
}

// IncErrorType increments a typed error counter.
func (m *Metrics) IncErrorType(errorType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errorTypes[errorType]++
}

// IncDetection increments a detection counter by rule and category.
func (m *Metrics) IncDetection(ruleID, category string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.detections[ruleID+"|"+category]++
}

// MetricsHandler serves a Prometheus-style plaintext metrics endpoint.
func (m *Metrics) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprintf(writer,
			"cast_requests_started %d\ncast_requests_completed %d\ncast_sse_requests %d\ncast_action_allow %d\ncast_action_redact %d\ncast_action_block %d\ncast_upstream_errors %d\n",
			m.requestsStarted.Load(),
			m.requestsCompleted.Load(),
			m.sseRequests.Load(),
			m.allowActions.Load(),
			m.redactActions.Load(),
			m.blockActions.Load(),
			m.upstreamErrors.Load(),
		)
		m.mu.Lock()
		errorKeys := make([]string, 0, len(m.errorTypes))
		for key := range m.errorTypes {
			errorKeys = append(errorKeys, key)
		}
		sort.Strings(errorKeys)
		for _, key := range errorKeys {
			_, _ = fmt.Fprintf(writer, "cast_errors_total{type=%q} %d\n", key, m.errorTypes[key])
		}
		detectionKeys := make([]string, 0, len(m.detections))
		for key := range m.detections {
			detectionKeys = append(detectionKeys, key)
		}
		sort.Strings(detectionKeys)
		for _, key := range detectionKeys {
			parts := strings.SplitN(key, "|", 2)
			if len(parts) != 2 {
				continue
			}
			_, _ = fmt.Fprintf(writer, "cast_detections_total{rule=%q,category=%q} %d\n", parts[0], parts[1], m.detections[key])
		}
		m.mu.Unlock()
	})
}

// HealthHandler serves a basic health response.
func (m *Metrics) HealthHandler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`{"status":"ok"}`))
	})
}
