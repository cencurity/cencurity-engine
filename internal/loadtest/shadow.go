package loadtest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cencurity-engine/internal/config"
	"cencurity-engine/internal/observability"
	"cencurity-engine/internal/proxy"
	"cencurity-engine/internal/rules"
)

// ShadowConfig controls a real-upstream direct-vs-proxy comparison run.
type ShadowConfig struct {
	UpstreamURL        string
	Provider           string
	APIKey             string
	Model              string
	Concurrency        int
	Iterations         int
	RequestTimeout     time.Duration
	PolicyFile         string
	Scenarios          []ShadowScenario
}

// ShadowComparison captures one real-upstream scenario result.
type ShadowComparison struct {
	Scenario            string
	ExpectedAction      string
	ObservedProxyAction string
	ProxyActionCounts   ActionStats
	ProxyConsistent     bool
	Direct              Summary
	Proxy               Summary
	MeanLatencyIncrease time.Duration
	P95LatencyIncrease  time.Duration
	ThroughputDropPct   float64
}

type shadowProvider string

const (
	shadowProviderOpenAI    shadowProvider = "openai"
	shadowProviderAnthropic shadowProvider = "anthropic"
	shadowProviderGemini    shadowProvider = "gemini"
)

type shadowRequestSpec struct {
	provider shadowProvider
	path     string
	query    url.Values
	headers  map[string]string
	body     []byte
}

// RunShadow executes direct-vs-proxy comparisons against a real upstream.
func RunShadow(cfg ShadowConfig) ([]ShadowComparison, error) {
	provider, err := resolveShadowProvider(cfg.Provider, cfg.UpstreamURL)
	if err != nil {
		return nil, err
	}
	requestSpec, err := buildShadowRequestSpec(provider, cfg.Model, cfg.APIKey, "")
	if err != nil {
		return nil, err
	}
	logger := observability.NewLogger("error")
	metrics := observability.NewMetrics()
	ruleManager, err := rules.NewManager(cfg.PolicyFile, time.Hour, logger)
	if err != nil {
		return nil, err
	}
	server, err := proxy.NewServer(config.Config{
		ListenAddr:           "127.0.0.1:0",
		UpstreamURL:          cfg.UpstreamURL,
		RequestTimeout:       cfg.RequestTimeout,
		ReadHeaderTimeout:    5 * time.Second,
		PolicyFile:           cfg.PolicyFile,
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

	directURL := buildShadowURL(strings.TrimRight(cfg.UpstreamURL, "/"), requestSpec.path, requestSpec.query)
	proxyURL := buildShadowURL("http://"+listener.Addr().String(), requestSpec.path, requestSpec.query)
	results := make([]ShadowComparison, 0, len(cfg.Scenarios))
	for _, scenario := range cfg.Scenarios {
		direct, _, _, _, err := runShadowScenario("direct", directURL, cfg, scenario, provider)
		if err != nil {
			return nil, err
		}
		proxySummary, observedAction, actionCounts, consistent, err := runShadowScenario("proxy", proxyURL, cfg, scenario, provider)
		if err != nil {
			return nil, err
		}
		results = append(results, ShadowComparison{
			Scenario:            scenario.Name,
			ExpectedAction:      scenario.ExpectedAction,
			ObservedProxyAction: observedAction,
			ProxyActionCounts:   actionCounts,
			ProxyConsistent:     consistent,
			Direct:              direct,
			Proxy:               proxySummary,
			MeanLatencyIncrease: proxySummary.Mean - direct.Mean,
			P95LatencyIncrease:  proxySummary.P95 - direct.P95,
			ThroughputDropPct:   percentDrop(direct.ThroughputRPS, proxySummary.ThroughputRPS),
		})
	}
	return results, nil
}

func runShadowScenario(name, endpoint string, cfg ShadowConfig, scenario ShadowScenario, provider shadowProvider) (Summary, string, ActionStats, bool, error) {
	client := &http.Client{Timeout: cfg.RequestTimeout}
	latencies := make([]time.Duration, 0, cfg.Concurrency*cfg.Iterations)
	var latenciesMu sync.Mutex
	var successes atomic.Uint64
	var timeouts atomic.Uint64
	var disconnects atomic.Uint64
	var parseFailures atomic.Uint64
	var otherFailures atomic.Uint64
	var allows atomic.Uint64
	var blocks atomic.Uint64
	var redacts atomic.Uint64
	stopSampling := make(chan struct{})
	peakHeap := samplePeakHeap(stopSampling)
	cpuStart, _ := processCPUTime()
	started := time.Now()

	var wg sync.WaitGroup
	for worker := 0; worker < cfg.Concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for attempt := 0; attempt < cfg.Iterations; attempt++ {
				requestStarted := time.Now()
				outcome, err := doRealStreamingRequest(client, endpoint, provider, cfg.APIKey, cfg.Model, scenario.Prompt)
				if err != nil {
					classifyFailure(err, &timeouts, &disconnects, &parseFailures, &otherFailures)
					continue
				}
				switch outcome {
				case "block":
					blocks.Add(1)
				case "redact":
					redacts.Add(1)
				default:
					allows.Add(1)
				}
				successes.Add(1)
				latenciesMu.Lock()
				latencies = append(latencies, time.Since(requestStarted))
				latenciesMu.Unlock()
			}
		}()
	}
	wg.Wait()
	close(stopSampling)
	wall := time.Since(started)
	cpuEnd, _ := processCPUTime()
	actionCounts := ActionStats{Allow: int(allows.Load()), Redact: int(redacts.Load()), Block: int(blocks.Load())}
	observed, consistent := summarizeActions(actionCounts)
	return buildSummary(name, cfg.Concurrency, cfg.Concurrency*cfg.Iterations, successes.Load(), timeouts.Load(), disconnects.Load(), parseFailures.Load(), otherFailures.Load(), latencies, wall, peakHeap.Load(), cpuEnd-cpuStart), observed, actionCounts, consistent, nil
}

func summarizeActions(stats ActionStats) (string, bool) {
	nonZero := 0
	observed := "allow"
	maxCount := stats.Allow
	if stats.Allow > 0 {
		nonZero++
	}
	if stats.Redact > 0 {
		nonZero++
		if stats.Redact > maxCount {
			maxCount = stats.Redact
			observed = "redact"
		}
	}
	if stats.Block > 0 {
		nonZero++
		if stats.Block > maxCount {
			observed = "block"
		}
	}
	return observed, nonZero <= 1
}

func doRealStreamingRequest(client *http.Client, endpoint string, provider shadowProvider, apiKey, model, prompt string) (string, error) {
	requestSpec, err := buildShadowRequestSpec(provider, model, apiKey, prompt)
	if err != nil {
		return "", err
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(requestSpec.body))
	if err != nil {
		return "", err
	}
	for key, value := range requestSpec.headers {
		request.Header.Set(key, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusBadRequest {
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return "", fmt.Errorf("unexpected status: %d body=%s", response.StatusCode, strings.TrimSpace(string(payload)))
	}
	reader := bufio.NewReader(response.Body)
	var transcript strings.Builder
	for {
		line, readErr := reader.ReadString('\n')
		if line != "" {
			transcript.WriteString(line)
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return "", readErr
		}
	}
	bodyText := transcript.String()
	if err := validateShadowTranscript(provider, bodyText); err != nil {
		return "", err
	}
	switch {
	case strings.Contains(bodyText, "blocked by cencurity"):
		return "block", nil
	case strings.Contains(bodyText, "[REDACTED]"):
		return "redact", nil
	default:
		return "allow", nil
	}
}

func resolveShadowProvider(override, upstreamURL string) (shadowProvider, error) {
	switch strings.ToLower(strings.TrimSpace(override)) {
	case "", "auto":
		return inferShadowProvider(upstreamURL), nil
	case string(shadowProviderOpenAI):
		return shadowProviderOpenAI, nil
	case string(shadowProviderAnthropic):
		return shadowProviderAnthropic, nil
	case string(shadowProviderGemini), "google":
		return shadowProviderGemini, nil
	default:
		return "", fmt.Errorf("unsupported shadow provider %q", override)
	}
}

func inferShadowProvider(upstreamURL string) shadowProvider {
	parsed, err := url.Parse(upstreamURL)
	if err != nil {
		return shadowProviderOpenAI
	}
	host := strings.ToLower(parsed.Host)
	path := strings.ToLower(parsed.Path)
	switch {
	case strings.Contains(host, "anthropic"):
		return shadowProviderAnthropic
	case strings.Contains(host, "google"), strings.Contains(host, "gemini"), strings.Contains(host, "generativelanguage"):
		return shadowProviderGemini
	case strings.Contains(path, "/v1/messages"):
		return shadowProviderAnthropic
	case strings.Contains(path, ":streamgeneratecontent"):
		return shadowProviderGemini
	default:
		return shadowProviderOpenAI
	}
}

func buildShadowRequestSpec(provider shadowProvider, model, apiKey, prompt string) (shadowRequestSpec, error) {
	spec := shadowRequestSpec{
		provider: provider,
		query:    url.Values{},
		headers:  map[string]string{"Content-Type": "application/json"},
	}
	switch provider {
	case shadowProviderAnthropic:
		spec.path = "/v1/messages"
		spec.headers["x-api-key"] = apiKey
		spec.headers["anthropic-version"] = "2023-06-01"
		body, err := json.Marshal(map[string]any{
			"model":      model,
			"max_tokens": 1024,
			"stream":     true,
			"messages":   []map[string]string{{"role": "user", "content": prompt}},
		})
		if err != nil {
			return shadowRequestSpec{}, err
		}
		spec.body = body
	case shadowProviderGemini:
		spec.path = fmt.Sprintf("/v1beta/models/%s:streamGenerateContent", model)
		spec.query.Set("alt", "sse")
		spec.headers["x-goog-api-key"] = apiKey
		body, err := json.Marshal(map[string]any{
			"contents": []map[string]any{{
				"role":  "user",
				"parts": []map[string]string{{"text": prompt}},
			}},
		})
		if err != nil {
			return shadowRequestSpec{}, err
		}
		spec.body = body
	default:
		spec.path = "/v1/chat/completions"
		spec.headers["Authorization"] = "Bearer " + apiKey
		body, err := json.Marshal(map[string]any{
			"model":    model,
			"stream":   true,
			"messages": []map[string]string{{"role": "user", "content": prompt}},
		})
		if err != nil {
			return shadowRequestSpec{}, err
		}
		spec.body = body
	}
	return spec, nil
}

func buildShadowURL(baseURL, requestPath string, query url.Values) string {
	endpoint := strings.TrimRight(baseURL, "/") + requestPath
	if len(query) == 0 {
		return endpoint
	}
		return endpoint + "?" + query.Encode()
}

func validateShadowTranscript(provider shadowProvider, transcript string) error {
	trimmed := strings.TrimSpace(transcript)
	if trimmed == "" {
		return fmt.Errorf("parse failure: empty stream")
	}
	switch provider {
	case shadowProviderAnthropic:
		if strings.Contains(trimmed, "event: message_stop") || strings.Contains(trimmed, `"type":"message_stop"`) || strings.Contains(trimmed, `"type": "message_stop"`) {
			return nil
		}
		if strings.Contains(trimmed, `"type":"error"`) || strings.Contains(trimmed, `"type": "error"`) {
			return nil
		}
		return fmt.Errorf("parse failure: missing anthropic terminal event")
	case shadowProviderGemini:
		if strings.Contains(trimmed, `"candidates"`) || strings.Contains(trimmed, `"promptFeedback"`) || strings.Contains(trimmed, `"error"`) {
			return nil
		}
		return fmt.Errorf("parse failure: missing gemini response payload")
	default:
		if strings.Contains(trimmed, "data: [DONE]") {
			return nil
		}
		return fmt.Errorf("parse failure: missing done event")
	}
}
