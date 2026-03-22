package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"
)

const (
	defaultListenAddr       = ":8080"
	defaultUpstreamURL      = "https://api.openai.com"
	defaultRequestTimeout   = 60 * time.Second
	defaultReadHeaderTimout = 10 * time.Second
	defaultPolicyReload     = 3 * time.Second
	defaultHealthPath       = "/healthz"
	defaultMetricsPath      = "/metrics"
	defaultLogFormat        = "pretty"
)

// Config holds runtime settings for the proxy engine.
type Config struct {
	ListenAddr        string
	UpstreamURL       string
	RequestTimeout    time.Duration
	ReadHeaderTimeout time.Duration
	PolicyFile        string
	PolicyReloadInterval time.Duration
	HealthPath        string
	MetricsPath       string
	LogLevel          string
	LogFormat         string
}

// Load reads configuration from environment variables and validates it.
func Load() (Config, error) {
	upstreamURL := getEnv("OPENAI_API_BASE_URL", "")
	if upstreamURL == "" {
		upstreamURL = getEnv("CENCURITY_UPSTREAM_URL", defaultUpstreamURL)
	}

	cfg := Config{
		ListenAddr:        getEnv("CENCURITY_LISTEN_ADDR", defaultListenAddr),
		UpstreamURL:       upstreamURL,
		RequestTimeout:    getDurationEnv("CENCURITY_REQUEST_TIMEOUT_MS", defaultRequestTimeout),
		ReadHeaderTimeout: getDurationEnv("CENCURITY_READ_HEADER_TIMEOUT_MS", defaultReadHeaderTimout),
		PolicyFile:        getEnv("CENCURITY_POLICY_FILE", ""),
		PolicyReloadInterval: getDurationEnv("CENCURITY_POLICY_RELOAD_MS", defaultPolicyReload),
		HealthPath:        getEnv("CENCURITY_HEALTH_PATH", defaultHealthPath),
		MetricsPath:       getEnv("CENCURITY_METRICS_PATH", defaultMetricsPath),
		LogLevel:          getEnv("CENCURITY_LOG_LEVEL", "info"),
		LogFormat:         getEnv("CENCURITY_LOG_FORMAT", defaultLogFormat),
	}

	parsed, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		return Config{}, fmt.Errorf("parse upstream url: %w", err)
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return Config{}, fmt.Errorf("CENCURITY_UPSTREAM_URL must include scheme and host")
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func getDurationEnv(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	milliseconds, err := strconv.Atoi(value)
	if err != nil || milliseconds <= 0 {
		return fallback
	}

	return time.Duration(milliseconds) * time.Millisecond
}
