package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"cencurity-engine/internal/loadtest"
)

func runShadowtest(args []string) error {
	fs := flag.NewFlagSet("shadowtest", flag.ContinueOnError)
	upstream := fs.String("upstream", "", "real upstream base URL")
	provider := fs.String("provider", "auto", "provider kind: auto, openai, anthropic, gemini")
	model := fs.String("model", "", "real upstream model name")
	apiKey := fs.String("api-key", "", "upstream API key")
	apiKeyFile := fs.String("api-key-file", "", "file containing the upstream API key")
	concurrency := fs.Int("concurrency", 1, "number of concurrent workers per scenario")
	iterations := fs.Int("iterations", 1, "requests per worker per scenario")
	timeout := fs.Duration("timeout", 90*time.Second, "request timeout")
	policyFile := fs.String("policy", "", "policy file path override")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *upstream == "" {
		return fmt.Errorf("--upstream is required")
	}
	if *model == "" {
		return fmt.Errorf("--model is required")
	}
	key, err := resolveAPIKey(*apiKey, *apiKeyFile)
	if err != nil {
		return err
	}
	if *concurrency <= 0 {
		return fmt.Errorf("--concurrency must be greater than 0")
	}
	if *iterations <= 0 {
		return fmt.Errorf("--iterations must be greater than 0")
	}

	results, err := loadtest.RunShadow(loadtest.ShadowConfig{
		UpstreamURL:    *upstream,
		Provider:       *provider,
		APIKey:         key,
		Model:          *model,
		Concurrency:    *concurrency,
		Iterations:     *iterations,
		RequestTimeout: *timeout,
		PolicyFile:     *policyFile,
		Scenarios:      loadtest.DefaultShadowScenarios(),
	})
	if err != nil {
		return err
	}

	for _, result := range results {
		fmt.Fprintf(os.Stdout, "scenario=%s expected=%s observed_proxy=%s consistent=%t actions=allow:%d redact:%d block:%d\n", result.Scenario, result.ExpectedAction, result.ObservedProxyAction, result.ProxyConsistent, result.ProxyActionCounts.Allow, result.ProxyActionCounts.Redact, result.ProxyActionCounts.Block)
		fmt.Fprintf(os.Stdout, "  direct: success=%d/%d min=%s p50=%s max=%s mean=%s throughput=%.2f rps timeouts=%d disconnects=%d parse_failures=%d other_failures=%d\n",
			result.Direct.Successes, result.Direct.TotalRequests, result.Direct.Min, result.Direct.P50, result.Direct.Max, result.Direct.Mean, result.Direct.ThroughputRPS, result.Direct.Timeouts, result.Direct.Disconnects, result.Direct.ParseFailures, result.Direct.OtherFailures,
		)
		fmt.Fprintf(os.Stdout, "  proxy : success=%d/%d min=%s p50=%s max=%s mean=%s throughput=%.2f rps timeouts=%d disconnects=%d parse_failures=%d other_failures=%d\n",
			result.Proxy.Successes, result.Proxy.TotalRequests, result.Proxy.Min, result.Proxy.P50, result.Proxy.Max, result.Proxy.Mean, result.Proxy.ThroughputRPS, result.Proxy.Timeouts, result.Proxy.Disconnects, result.Proxy.ParseFailures, result.Proxy.OtherFailures,
		)
		fmt.Fprintf(os.Stdout, "  delta : mean_latency=%s p95_latency=%s throughput_drop=%.2f%%\n", result.MeanLatencyIncrease, result.P95LatencyIncrease, result.ThroughputDropPct)
	}
	return nil
}

func resolveAPIKey(raw, path string) (string, error) {
	if strings.TrimSpace(raw) != "" {
		return strings.TrimSpace(raw), nil
	}
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("either --api-key or --api-key-file is required")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(content))
	if key == "" {
		return "", fmt.Errorf("api key file is empty")
	}
	return key, nil
}
