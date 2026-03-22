package loadtest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cencurity-engine/internal/config"
	"cencurity-engine/internal/observability"
	"cencurity-engine/internal/proxy"
	"cencurity-engine/internal/rules"
)

// Run executes direct-vs-proxy load tests and returns comparable summaries.
func Run(cfg Config) ([]Comparison, error) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		streamSynthetic(writer, cfg.Chunks, cfg.ChunkBytes)
	}))
	defer upstream.Close()

	logger := observability.NewLogger("error")
	metrics := observability.NewMetrics()
	ruleManager, err := rules.NewManager("", time.Hour, logger)
	if err != nil {
		return nil, err
	}
	server, err := proxy.NewServer(config.Config{
		ListenAddr:           "127.0.0.1:0",
		UpstreamURL:          upstream.URL,
		RequestTimeout:       cfg.RequestTimeout,
		ReadHeaderTimeout:    5 * time.Second,
		PolicyReloadInterval: time.Hour,
		HealthPath:           "/healthz",
		MetricsPath:          "/metrics",
		LogLevel:             "error",
	}, logger, metrics, ruleManager)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Serve(listener)
	}()
	defer func() {
		_ = server.Shutdown(context.Background())
		select {
		case <-serverErr:
		default:
		}
	}()

	proxyURL := "http://" + listener.Addr().String() + "/v1/chat/completions"
	directURL := upstream.URL + "/v1/chat/completions"
	comparisons := make([]Comparison, 0, len(cfg.Concurrency))
	for _, concurrency := range cfg.Concurrency {
		direct, err := runScenario("direct", directURL, concurrency, cfg)
		if err != nil {
			return nil, err
		}
		proxySummary, err := runScenario("proxy", proxyURL, concurrency, cfg)
		if err != nil {
			return nil, err
		}
		comparisons = append(comparisons, Comparison{
			Concurrency:         concurrency,
			Direct:              direct,
			Proxy:               proxySummary,
			MeanLatencyIncrease: proxySummary.Mean - direct.Mean,
			P95LatencyIncrease:  proxySummary.P95 - direct.P95,
			ThroughputDropPct:   percentDrop(direct.ThroughputRPS, proxySummary.ThroughputRPS),
		})
	}
	return comparisons, nil
}

func runScenario(name, endpoint string, concurrency int, cfg Config) (Summary, error) {
	client := &http.Client{Timeout: cfg.RequestTimeout}
	latencies := make([]time.Duration, 0, concurrency*cfg.RequestsPerWorker)
	var latenciesMu sync.Mutex
	var successes atomic.Uint64
	var timeouts atomic.Uint64
	var disconnects atomic.Uint64
	var parseFailures atomic.Uint64
	var otherFailures atomic.Uint64
	stopSampling := make(chan struct{})
	peakHeap := samplePeakHeap(stopSampling)
	cpuStart, _ := processCPUTime()
	started := time.Now()

	var wg sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for requestIndex := 0; requestIndex < cfg.RequestsPerWorker; requestIndex++ {
				requestStarted := time.Now()
				if err := doStreamingRequest(client, endpoint); err != nil {
					classifyFailure(err, &timeouts, &disconnects, &parseFailures, &otherFailures)
					continue
				}
				successes.Add(1)
				latenciesMu.Lock()
				latencies = append(latencies, time.Since(requestStarted))
				latenciesMu.Unlock()
			}
		}(worker)
	}
	wg.Wait()
	close(stopSampling)
	wall := time.Since(started)
	cpuEnd, _ := processCPUTime()
	summary := buildSummary(name, concurrency, cfg.RequestsPerWorker*concurrency, successes.Load(), timeouts.Load(), disconnects.Load(), parseFailures.Load(), otherFailures.Load(), latencies, wall, peakHeap.Load(), cpuEnd-cpuStart)
	return summary, nil
}

func doStreamingRequest(client *http.Client, endpoint string) error {
	body, err := json.Marshal(map[string]any{
		"model":   "synthetic-model",
		"stream":  true,
		"messages": []map[string]string{{"role": "user", "content": "generate safe code"}},
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", response.StatusCode)
	}
	reader := bufio.NewReader(response.Body)
	sawDone := false
	for {
		line, readErr := reader.ReadString('\n')
		if line != "" && strings.TrimSpace(line) == "data: [DONE]" {
			sawDone = true
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return readErr
		}
	}
	if !sawDone {
		return fmt.Errorf("parse failure: missing done event")
	}
	return nil
}

func streamSynthetic(writer http.ResponseWriter, chunks, chunkBytes int) {
	writer.Header().Set("Content-Type", "text/event-stream")
	flusher, _ := writer.(http.Flusher)
	chunk := strings.Repeat("a", max(1, chunkBytes))
	for index := 0; index < chunks; index++ {
		payload := fmt.Sprintf("data: {\"id\":\"synthetic\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":%q}}]}\n\n", chunk)
		_, _ = writer.Write([]byte(payload))
		if flusher != nil {
			flusher.Flush()
		}
	}
	_, _ = writer.Write([]byte("data: [DONE]\n\n"))
	if flusher != nil {
		flusher.Flush()
	}
}

func buildSummary(name string, concurrency, total int, successCount, timeoutCount, disconnectCount, parseFailureCount, otherFailureCount uint64, latencies []time.Duration, wall time.Duration, peakHeap uint64, cpuDelta time.Duration) Summary {
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	mean := averageLatency(latencies)
	wallSeconds := wall.Seconds()
	throughput := 0.0
	if wallSeconds > 0 {
		throughput = float64(successCount) / wallSeconds
	}
	cpuPercent := 0.0
	if wall > 0 {
		cpuPercent = (float64(cpuDelta) / float64(wall)) * 100
	}
	return Summary{
		Name:             name,
		Concurrency:      concurrency,
		TotalRequests:    total,
		Successes:        int(successCount),
		Timeouts:         int(timeoutCount),
		Disconnects:      int(disconnectCount),
		ParseFailures:    int(parseFailureCount),
		OtherFailures:    int(otherFailureCount),
		Min:              minLatency(latencies),
		Max:              maxLatency(latencies),
		P50:              percentile(latencies, 50),
		P95:              percentile(latencies, 95),
		P99:              percentile(latencies, 99),
		Mean:             mean,
		ThroughputRPS:    throughput,
		WallTime:         wall,
		PeakHeapBytes:    peakHeap,
		ApproxCPUPercent: cpuPercent,
	}
}

func percentile(values []time.Duration, percentile int) time.Duration {
	if len(values) == 0 {
		return 0
	}
	index := int(math.Ceil((float64(percentile) / 100) * float64(len(values))))
	if index <= 0 {
		index = 1
	}
	if index > len(values) {
		index = len(values)
	}
	return values[index-1]
}

func averageLatency(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	var total time.Duration
	for _, value := range values {
		total += value
	}
	return total / time.Duration(len(values))
}

func minLatency(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	return values[0]
}

func maxLatency(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	return values[len(values)-1]
}

func samplePeakHeap(stop <-chan struct{}) *atomic.Uint64 {
	var peak atomic.Uint64
	go func() {
		var mem runtime.MemStats
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				runtime.ReadMemStats(&mem)
				for {
					current := peak.Load()
					if mem.HeapAlloc <= current || peak.CompareAndSwap(current, mem.HeapAlloc) {
						break
					}
				}
			}
		}
	}()
	return &peak
}

func classifyFailure(err error, timeouts, disconnects, parseFailures, otherFailures *atomic.Uint64) {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "timeout"):
		timeouts.Add(1)
	case strings.Contains(message, "broken pipe") || strings.Contains(message, "connection reset"):
		disconnects.Add(1)
	case strings.Contains(message, "parse failure"):
		parseFailures.Add(1)
	default:
		otherFailures.Add(1)
	}
}

func percentDrop(baseline, current float64) float64 {
	if baseline == 0 {
		return 0
	}
	return ((baseline - current) / baseline) * 100
}

func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}
