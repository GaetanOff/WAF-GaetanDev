package logger

import (
	"io"
	"os"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/rs/zerolog"
)

type Logger struct {
	logger zerolog.Logger
	now    func() time.Time
}

func New(cfg config.Logging) Logger {
	output := io.Writer(os.Stdout)
	if cfg.Output == "stderr" {
		output = os.Stderr
	}
	return NewWithWriter(cfg, output)
}

func NewWithWriter(cfg config.Logging, output io.Writer) Logger {
	level, err := zerolog.ParseLevel(cfg.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	return Logger{
		logger: zerolog.New(output).Level(level),
		now:    time.Now,
	}
}

func (l Logger) WriteSecurityEvent(event SecurityEvent) {
	l.logger.Log().
		Str("timestamp", event.Timestamp).
		Str("request_id", event.RequestID).
		Str("ip", event.IP).
		Str("ip_hash", event.IPHash).
		Str("domain", event.Domain).
		Str("method", event.Method).
		Str("path", event.Path).
		Str("user_agent", event.UserAgent).
		Str("action", event.Action).
		Str("reason", event.Reason).
		Int("trust_score", event.TrustScore).
		Float64("latency_ms", event.LatencyMS).
		Float64("waf_latency_ms", event.WAFLatencyMS).
		RawJSON("upstream_status", nullableInt(event.UpstreamStatus)).
		RawJSON("cf_ray", nullableString(event.CFRay)).
		RawJSON("cf_country", nullableString(event.CFCountry)).
		Send()
}
