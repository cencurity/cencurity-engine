package cli

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"cencurity-engine/internal/config"
	"cencurity-engine/internal/loadtest"
	"cencurity-engine/internal/observability"
	"cencurity-engine/internal/proxy"
	"cencurity-engine/internal/rules"
)

const version = "0.1.0"

// Run executes the CAST CLI.
func Run(args []string) error {
	if len(args) == 0 {
		return runServe(nil)
	}

	switch args[0] {
	case "serve":
		return runServe(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "loadtest":
		return runLoadtest(args[1:])
	case "shadowtest":
		return runShadowtest(args[1:])
	case "version":
		fmt.Println(version)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "", "listen address override")
	upstream := fs.String("upstream", "", "upstream base URL override")
	policyFile := fs.String("policy", "", "policy file path override")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.ListenAddr = *listen
	}
	if *upstream != "" {
		cfg.UpstreamURL = *upstream
	}
	if *policyFile != "" {
		cfg.PolicyFile = *policyFile
	}

	logger := observability.NewLogger(cfg.LogLevel, cfg.LogFormat)
	metrics := observability.NewMetrics()
	ruleManager, err := rules.NewManager(cfg.PolicyFile, cfg.PolicyReloadInterval, logger)
	if err != nil {
		return err
	}

	server, err := proxy.NewServer(cfg, logger, metrics, ruleManager)
	if err != nil {
		return err
	}

	logger.Info("cast_server_starting", "listen_addr", cfg.ListenAddr, "upstream_url", cfg.UpstreamURL)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func runDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger := observability.NewLogger(cfg.LogLevel, cfg.LogFormat)
	manager, err := rules.NewManager(cfg.PolicyFile, time.Hour, logger)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "CAST version: %s\n", version)
	fmt.Fprintf(os.Stdout, "Listen address: %s\n", cfg.ListenAddr)
	fmt.Fprintf(os.Stdout, "Upstream URL: %s\n", cfg.UpstreamURL)
	fmt.Fprintf(os.Stdout, "Policy file: %s\n", cfg.PolicyFile)
	fmt.Fprintf(os.Stdout, "Active rules: %d\n", len(manager.Rules()))
	return nil
}

func runLoadtest(args []string) error {
	fs := flag.NewFlagSet("loadtest", flag.ContinueOnError)
	concurrency := fs.String("concurrency", "10,50,100", "comma-separated concurrency levels")
	requestsPerWorker := fs.Int("requests-per-worker", 2, "requests to issue per worker")
	chunks := fs.Int("chunks", 512, "SSE chunks per response")
	chunkBytes := fs.Int("chunk-bytes", 256, "payload bytes per chunk")
	timeout := fs.Duration("timeout", 30*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	levels, err := parseConcurrency(*concurrency)
	if err != nil {
		return err
	}

	comparisons, err := loadtest.Run(loadtest.Config{
		Concurrency:       levels,
		RequestsPerWorker: *requestsPerWorker,
		Chunks:            *chunks,
		ChunkBytes:        *chunkBytes,
		RequestTimeout:    *timeout,
	})
	if err != nil {
		return err
	}

	for _, comparison := range comparisons {
		fmt.Fprintf(os.Stdout, "concurrency=%d\n", comparison.Concurrency)
		fmt.Fprintf(os.Stdout, "  direct: success=%d/%d p50=%s p95=%s p99=%s mean=%s throughput=%.2f rps peak_heap=%d cpu=%.2f%% timeouts=%d disconnects=%d parse_failures=%d other_failures=%d\n",
			comparison.Direct.Successes, comparison.Direct.TotalRequests, comparison.Direct.P50, comparison.Direct.P95, comparison.Direct.P99, comparison.Direct.Mean, comparison.Direct.ThroughputRPS, comparison.Direct.PeakHeapBytes, comparison.Direct.ApproxCPUPercent, comparison.Direct.Timeouts, comparison.Direct.Disconnects, comparison.Direct.ParseFailures, comparison.Direct.OtherFailures,
		)
		fmt.Fprintf(os.Stdout, "  proxy : success=%d/%d p50=%s p95=%s p99=%s mean=%s throughput=%.2f rps peak_heap=%d cpu=%.2f%% timeouts=%d disconnects=%d parse_failures=%d other_failures=%d\n",
			comparison.Proxy.Successes, comparison.Proxy.TotalRequests, comparison.Proxy.P50, comparison.Proxy.P95, comparison.Proxy.P99, comparison.Proxy.Mean, comparison.Proxy.ThroughputRPS, comparison.Proxy.PeakHeapBytes, comparison.Proxy.ApproxCPUPercent, comparison.Proxy.Timeouts, comparison.Proxy.Disconnects, comparison.Proxy.ParseFailures, comparison.Proxy.OtherFailures,
		)
		fmt.Fprintf(os.Stdout, "  delta : mean_latency=%s p95_latency=%s throughput_drop=%.2f%%\n", comparison.MeanLatencyIncrease, comparison.P95LatencyIncrease, comparison.ThroughputDropPct)
	}
	return nil
}

func parseConcurrency(raw string) ([]int, error) {
	parts := strings.Split(raw, ",")
	levels := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		value, err := strconv.Atoi(part)
		if err != nil || value <= 0 {
			return nil, fmt.Errorf("invalid concurrency level %q", part)
		}
		levels = append(levels, value)
	}
	if len(levels) == 0 {
		return nil, fmt.Errorf("at least one concurrency level is required")
	}
	return levels, nil
}
