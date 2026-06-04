package logger

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/trust"
	"github.com/google/uuid"
)

func TestMiddlewareWritesSecurityEventJSONWithoutQueryString(t *testing.T) {
	var output bytes.Buffer
	log := NewWithWriter(config.Default().Logging, &output)
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	log.now = func() time.Time { return now }
	scores, store := newTestScoreManager(t)
	defer store.Close()
	scores.Set("1.2.3.4", "example.test", 42)
	handler := log.Middleware(scores, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if RequestID(r) == "" {
			t.Fatal("request id was not injected into context")
		}
		r.Header.Set("X-WAF-Action", ActionChallenge)
		r.Header.Set("X-WAF-Reason", "score_below_challenge_threshold")
		w.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://example.test/search?q=secret", nil)
	request.RemoteAddr = "1.2.3.4:1234"
	request.Header.Set("User-Agent", "Mozilla/5.0")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Header().Get(requestIDHeader) == "" {
		t.Fatal("response missing X-Request-ID")
	}
	event := decodeEvent(t, output.String())
	assertRequiredString(t, event, "timestamp")
	assertRequiredString(t, event, "request_id")
	if _, err := uuid.Parse(event["request_id"].(string)); err != nil {
		t.Fatalf("request_id is not a UUID: %v", err)
	}
	if event["path"] != "/search" {
		t.Fatalf("path = %q, want /search", event["path"])
	}
	if strings.Contains(output.String(), "secret") {
		t.Fatalf("log contains query string: %s", output.String())
	}
	if event["action"] != ActionChallenge {
		t.Fatalf("action = %q, want %s", event["action"], ActionChallenge)
	}
	if event["reason"] != "score_below_challenge_threshold" {
		t.Fatalf("reason = %q", event["reason"])
	}
	if event["trust_score"] != float64(42) {
		t.Fatalf("trust_score = %v, want 42", event["trust_score"])
	}
	if _, ok := event["level"]; ok {
		t.Fatal("security event must not include non-schema field level")
	}
	if _, ok := event["message"]; ok {
		t.Fatal("security event must not include non-schema field message")
	}
}

func TestMiddlewareLogsRateLimitActionFromResponseHeaders(t *testing.T) {
	var output bytes.Buffer
	log := NewWithWriter(config.Default().Logging, &output)
	scores, store := newTestScoreManager(t)
	defer store.Close()
	handler := log.Middleware(scores, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-WAF-Action", ActionRateLimit)
		w.Header().Set("X-WAF-Reason", "rate_limit_exceeded")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://example.test/api", nil)
	request.RemoteAddr = "1.2.3.4:1234"

	handler.ServeHTTP(httptest.NewRecorder(), request)

	event := decodeEvent(t, output.String())
	if event["action"] != ActionRateLimit {
		t.Fatalf("action = %q, want %s", event["action"], ActionRateLimit)
	}
	if event["upstream_status"] != nil {
		t.Fatalf("upstream_status = %v, want null", event["upstream_status"])
	}
}

func decodeEvent(t *testing.T, raw string) map[string]any {
	t.Helper()

	var event map[string]any
	if err := json.Unmarshal([]byte(raw), &event); err != nil {
		t.Fatalf("invalid json log %q: %v", raw, err)
	}
	return event
}

func assertRequiredString(t *testing.T, event map[string]any, name string) {
	t.Helper()

	value, ok := event[name].(string)
	if !ok || value == "" {
		t.Fatalf("%s missing or empty in event %v", name, event)
	}
}

func newTestScoreManager(t *testing.T) (*trust.ScoreManager, *memory.Store) {
	t.Helper()

	store := memory.New(100)
	cfg := config.Default()
	cfg.Version = "1.0"
	cfg.Server.Listen = ":0"
	cfg.Upstream.Address = "http://example.test"
	cfg.Challenge.Enabled = false
	cfg.Admin.Enabled = false
	manager, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	return manager, store
}
