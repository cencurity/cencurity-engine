package proxy

import (
	"fmt"
	"log/slog"
	"net/http"

	"cencurity-engine/internal/config"
	"cencurity-engine/internal/detect"
	"cencurity-engine/internal/observability"
	"cencurity-engine/internal/policy"
	"cencurity-engine/internal/rules"
	"cencurity-engine/internal/stream"
)

// NewServer builds the HTTP server for the proxy engine.
func NewServer(cfg config.Config, logger *slog.Logger, metrics *observability.Metrics, ruleManager *rules.Manager) (*http.Server, error) {
	upstream, err := NewUpstream(cfg)
	if err != nil {
		return nil, fmt.Errorf("create upstream: %w", err)
	}

	interceptor := stream.NewInterceptor(detect.NewScanner(ruleManager), policy.NewEngine(ruleManager), logger, metrics)
	handler := NewHandler(upstream, interceptor, logger, metrics)
	mux := http.NewServeMux()
	mux.Handle(cfg.HealthPath, metrics.HealthHandler())
	mux.Handle(cfg.MetricsPath, metrics.MetricsHandler())
	mux.Handle("/", handler)

	return &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
	}, nil
}
