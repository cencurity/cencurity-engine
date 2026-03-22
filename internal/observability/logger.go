package observability

import (
	"log/slog"
	"os"
	"strings"
)

// NewLogger creates a logger for CLI and server output.
func NewLogger(level string, formats ...string) *slog.Logger {
	var logLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	format := "pretty"
	if len(formats) > 0 && strings.TrimSpace(formats[0]) != "" {
		format = strings.ToLower(strings.TrimSpace(formats[0]))
	}

	options := &slog.HandlerOptions{Level: logLevel}
	var handler slog.Handler
	switch format {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, options)
	case "pretty":
		handler = newPrettyHandler(os.Stdout, options)
	default:
		handler = slog.NewTextHandler(os.Stdout, options)
	}

	return slog.New(handler)
}
