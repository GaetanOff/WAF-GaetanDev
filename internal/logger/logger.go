package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gaetandev/waf/internal/config"
)

// Logger émet les événements de sécurité en JSON structuré via la bibliothèque
// standard log/slog. La sortie est conforme à security-event.schema.json :
// les clés intégrées de slog (time, level, msg) sont retirées.
type Logger struct {
	logger *slog.Logger
	level  slog.Level
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
	level := parseLevel(cfg.Level)
	handler := slog.NewJSONHandler(output, &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: dropBuiltinKeys,
	})
	return Logger{
		logger: slog.New(handler),
		level:  level,
		now:    time.Now,
	}
}

// WriteSecurityEvent journalise un événement de sécurité. Il est émis au niveau
// configuré afin de toujours passer le filtre du handler (les événements de
// sécurité constituent le journal d'audit, jamais filtrés par verbosité).
func (l Logger) WriteSecurityEvent(event SecurityEvent) {
	l.logger.LogAttrs(context.Background(), l.level, "",
		slog.String("timestamp", event.Timestamp),
		slog.String("request_id", event.RequestID),
		slog.String("ip", event.IP),
		slog.String("ip_hash", event.IPHash),
		slog.String("domain", event.Domain),
		slog.String("method", event.Method),
		slog.String("path", event.Path),
		slog.String("user_agent", event.UserAgent),
		slog.String("action", event.Action),
		slog.String("reason", event.Reason),
		slog.Int("trust_score", event.TrustScore),
		slog.Int("score_delta", event.ScoreDelta),
		slog.Float64("latency_ms", event.LatencyMS),
		slog.Float64("waf_latency_ms", event.WAFLatencyMS),
		nullableInt("upstream_status", event.UpstreamStatus),
		nullableString("cf_ray", event.CFRay),
		nullableString("cf_country", event.CFCountry),
	)
}

// parseLevel mappe le niveau de configuration vers un slog.Level (info par défaut).
func parseLevel(name string) slog.Level {
	switch strings.ToLower(name) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// dropBuiltinKeys retire les clés ajoutées par défaut par slog (time, level,
// msg) pour respecter security-event.schema.json (additionalProperties: false).
func dropBuiltinKeys(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 {
		switch a.Key {
		case slog.TimeKey, slog.LevelKey, slog.MessageKey:
			return slog.Attr{}
		}
	}
	return a
}
