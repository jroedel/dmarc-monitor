// Package logger builds the program's slog handler.
//
// It exists mostly to make one decision in one place: this program runs
// unattended from a timer, so its log is read after the fact by someone asking
// "did it run, and why did it not tell me about X". Text output goes to stderr
// so that a cron mail wrapper picks it up; JSON is available for a host that
// ships logs somewhere structured.
package logger

import (
	"io"
	"log/slog"
	"strings"
)

// Format selects the handler.
type Format string

const (
	// FormatText is human-readable key=value, the default.
	FormatText Format = "text"

	// FormatJSON is one JSON object per line.
	FormatJSON Format = "json"
)

// New builds a logger writing to w.
func New(w io.Writer, format Format, debug bool) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}

	opts := slog.HandlerOptions{Level: level}

	var handler slog.Handler
	switch strings.ToLower(string(format)) {
	case string(FormatJSON):
		handler = slog.NewJSONHandler(w, &opts)
	default:
		handler = slog.NewTextHandler(w, &opts)
	}

	return slog.New(handler)
}
