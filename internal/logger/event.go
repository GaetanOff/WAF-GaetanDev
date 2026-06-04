package logger

import (
	"encoding/json"
	"fmt"
)

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
	LatencyMS      float64
	WAFLatencyMS   float64
	UpstreamStatus *int
	CFRay          *string
	CFCountry      *string
}

func nullableInt(value *int) json.RawMessage {
	if value == nil {
		return json.RawMessage("null")
	}
	return json.RawMessage(fmt.Sprintf("%d", *value))
}

func nullableString(value *string) json.RawMessage {
	if value == nil || *value == "" {
		return json.RawMessage("null")
	}
	raw, _ := json.Marshal(*value)
	return raw
}
