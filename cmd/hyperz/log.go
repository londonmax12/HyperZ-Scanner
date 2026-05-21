package main

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// newLogger builds a *slog.Logger from --log-level and --log-format. The
// CLI hands the result to scanner/crawler/fingerprint via their existing
// callbacks so per-event prints (skip, error, fingerprint, proxy) end up
// as structured records on the same writer (stderr by default).
//
// Format "text" produces key=value lines; "json" produces one JSON object
// per record, suitable for piping to jq.
func newLogger(level, format string, w io.Writer) (*slog.Logger, error) {
	lvl, err := parseLogLevel(level)
	if err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	switch strings.ToLower(format) {
	case "", "text":
		h = slog.NewTextHandler(w, opts)
	case "json":
		h = slog.NewJSONHandler(w, opts)
	default:
		return nil, fmt.Errorf("unknown log format %q (want text|json)", format)
	}
	return slog.New(h), nil
}

func parseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q (want debug|info|warn|error)", s)
	}
}
