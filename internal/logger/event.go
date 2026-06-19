package logger

import "log/slog"

const (
	ActionPass         = "PASS"
	ActionChallenge    = "CHALLENGE"
	ActionBlock        = "BLOCK"
	ActionRateLimit    = "RATE_LIMIT"
	ActionCircuitBreak = "CIRCUIT_BREAK"
	ActionHoneypot     = "HONEYPOT"
)

type SecurityEvent struct {
	Timestamp      string
	RequestID      string
	IP             string
	IPHash         string
	Domain         string
	Method         string
	Path           string
	UserAgent      string
	Action         string
	Reason         string
	TrustScore     int
	ScoreDelta     int
	RiskScore      int
	RiskDecision   string
	RiskConfidence float64
	ShadowMode     bool
	GlobalPressure string
	UnderAttack    bool
	LatencyMS      float64
	WAFLatencyMS   float64
	UpstreamStatus *int
	CFRay          *string
	CFCountry      *string
}

// nullableInt rend un attribut entier, ou JSON null si la valeur est absente.
func nullableInt(key string, value *int) slog.Attr {
	if value == nil {
		return slog.Any(key, nil)
	}
	return slog.Int(key, *value)
}

// nullableString rend un attribut chaîne, ou JSON null si absente ou vide.
func nullableString(key string, value *string) slog.Attr {
	if value == nil || *value == "" {
		return slog.Any(key, nil)
	}
	return slog.String(key, *value)
}
