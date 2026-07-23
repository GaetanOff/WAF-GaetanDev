package logger

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/alert"
	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/trust"
	"github.com/gaetandev/waf/internal/upstreamtime"
	"github.com/google/uuid"
)

type recordingAlerter struct{ calls int }

func (a *recordingAlerter) Notify(alert.Event) { a.calls++ }

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

// Un 5xx renvoyé par l'UPSTREAM (origine down) ne pose pas X-WAF-Action : ce
// n'est pas un blocage WAF. Il doit être loggé action=PASS avec le vrai
// upstream_status, et ne JAMAIS déclencher d'alerte webhook (sinon spam à chaque
// hoquet d'origine).
func TestMiddlewareUpstream5xxIsPassNotBlock(t *testing.T) {
	var output bytes.Buffer
	log := NewWithWriter(config.Default().Logging, &output)
	alerter := &recordingAlerter{}
	log.Alerter = alerter
	scores, store := newTestScoreManager(t)
	defer store.Close()
	handler := log.Middleware(scores, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway) // origine down, aucune décision WAF
	}))
	request := httptest.NewRequest(http.MethodGet, "http://grafana.example/", nil)
	request.RemoteAddr = "1.2.3.4:1234"

	handler.ServeHTTP(httptest.NewRecorder(), request)

	event := decodeEvent(t, output.String())
	if event["action"] != ActionPass {
		t.Fatalf("action = %q, want PASS (un 5xx upstream n'est pas un blocage WAF)", event["action"])
	}
	if event["upstream_status"] != float64(http.StatusBadGateway) {
		t.Fatalf("upstream_status = %v, want 502", event["upstream_status"])
	}
	if alerter.calls != 0 {
		t.Fatalf("alerter appelé %d fois, want 0 (pas de fausse alerte sur 5xx upstream)", alerter.calls)
	}
}

// Un vrai blocage WAF (X-WAF-Action posé) doit rester BLOCK et alerter.
func TestMiddlewareRealBlockStillAlerts(t *testing.T) {
	var output bytes.Buffer
	log := NewWithWriter(config.Default().Logging, &output)
	alerter := &recordingAlerter{}
	log.Alerter = alerter
	scores, store := newTestScoreManager(t)
	defer store.Close()
	handler := log.Middleware(scores, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-WAF-Action", ActionBlock)
		w.Header().Set("X-WAF-Reason", "blacklist")
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "1.2.3.4:1234"

	handler.ServeHTTP(httptest.NewRecorder(), request)

	event := decodeEvent(t, output.String())
	if event["action"] != ActionBlock {
		t.Fatalf("action = %q, want BLOCK", event["action"])
	}
	if alerter.calls != 1 {
		t.Fatalf("alerter appelé %d fois, want 1 (vrai blocage WAF)", alerter.calls)
	}
}

// waf_latency_ms doit exclure le temps upstream : ici total = 100ms, upstream =
// 40ms → waf = 60ms (et non 100ms comme avant, où c'était un doublon du total).
func TestMiddlewareWAFLatencyExcludesUpstream(t *testing.T) {
	var output bytes.Buffer
	log := NewWithWriter(config.Default().Logging, &output)
	t0 := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	times := []time.Time{t0, t0.Add(100 * time.Millisecond)}
	idx := 0
	log.now = func() time.Time {
		v := times[idx]
		if idx < len(times)-1 {
			idx++
		}
		return v
	}
	scores, store := newTestScoreManager(t)
	defer store.Close()
	handler := log.Middleware(scores, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamtime.FromContext(r.Context()).Add(40 * time.Millisecond) // simule l'upstream
		w.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "1.2.3.4:1234"

	handler.ServeHTTP(httptest.NewRecorder(), request)

	event := decodeEvent(t, output.String())
	if event["latency_ms"] != float64(100) {
		t.Fatalf("latency_ms = %v, want 100", event["latency_ms"])
	}
	if event["waf_latency_ms"] != float64(60) {
		t.Fatalf("waf_latency_ms = %v, want 60 (total - upstream)", event["waf_latency_ms"])
	}
}

// TestSecurityEventJSONStaysWithinSchema vérifie que la sortie slog ne contient
// aucune clé hors de security-event.schema.json (additionalProperties: false),
// notamment les clés intégrées de slog (time, level, msg).
func TestSecurityEventJSONStaysWithinSchema(t *testing.T) {
	// Propriétés autorisées par specs/schemas/security-event.schema.json.
	allowed := map[string]bool{
		"timestamp": true, "request_id": true, "ip": true, "ip_hash": true,
		"domain": true, "method": true, "path": true, "user_agent": true,
		"action": true, "reason": true, "trust_score": true, "score_delta": true,
		"risk_score": true, "risk_decision": true, "risk_confidence": true, "shadow_mode": true,
		"global_pressure": true, "under_attack": true,
		"latency_ms": true, "waf_latency_ms": true, "upstream_status": true,
		"cf_ray": true, "cf_country": true,
	}

	var output bytes.Buffer
	log := NewWithWriter(config.Default().Logging, &output)
	scores, store := newTestScoreManager(t)
	defer store.Close()
	handler := log.Middleware(scores, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
	request.RemoteAddr = "1.2.3.4:1234"

	handler.ServeHTTP(httptest.NewRecorder(), request)

	event := decodeEvent(t, output.String())
	for key := range event {
		if !allowed[key] {
			t.Fatalf("emitted non-schema key %q in %v", key, event)
		}
	}
	for _, builtin := range []string{"time", "level", "msg"} {
		if _, ok := event[builtin]; ok {
			t.Fatalf("slog builtin key %q must be stripped", builtin)
		}
	}
}

// Un CF-Ray et un CF-IPCountry bien formés (trafic Cloudflare légitime) sont
// journalisés tels quels, le code pays étant normalisé en majuscules.
func TestMiddlewareLogsWellFormedCloudflareHeaders(t *testing.T) {
	var output bytes.Buffer
	log := NewWithWriter(config.Default().Logging, &output)
	scores, store := newTestScoreManager(t)
	defer store.Close()
	handler := log.Middleware(scores, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "1.2.3.4:1234"
	request.Header.Set("CF-Ray", "8f2a1b3c4d5e6f70-CDG")
	request.Header.Set("CF-IPCountry", "fr")

	handler.ServeHTTP(httptest.NewRecorder(), request)

	event := decodeEvent(t, output.String())
	if event["cf_ray"] != "8f2a1b3c4d5e6f70-CDG" {
		t.Fatalf("cf_ray = %v, want 8f2a1b3c4d5e6f70-CDG", event["cf_ray"])
	}
	if event["cf_country"] != "FR" {
		t.Fatalf("cf_country = %v, want FR (normalisé en majuscules)", event["cf_country"])
	}
}

// Un client atteignant l'origine hors Cloudflare peut forger ces en-têtes : la
// valeur ne doit jamais atteindre le journal telle quelle. Les caractères de
// contrôle / injection sont retirés du CF-Ray, et un code pays non conforme est
// abandonné (null) plutôt que journalisé (log forging, CWE-117).
func TestMiddlewareSanitizesForgedCloudflareHeaders(t *testing.T) {
	var output bytes.Buffer
	log := NewWithWriter(config.Default().Logging, &output)
	scores, store := newTestScoreManager(t)
	defer store.Close()
	handler := log.Middleware(scores, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "1.2.3.4:1234"
	// Tentative d'injection d'une fausse ligne de log via CF-Ray.
	request.Header.Set("CF-Ray", "abc\r\n{\"action\":\"forged\"} DROP")
	// Code pays invalide (trop long + caractères de contrôle).
	request.Header.Set("CF-IPCountry", "F\nR!")

	handler.ServeHTTP(httptest.NewRecorder(), request)

	event := decodeEvent(t, output.String())
	// slog échappe déjà les caractères de contrôle dans le JSON ; l'assertion
	// forte est que la valeur journalisée est exactement la forme filtrée,
	// débarrassée des sauts de ligne, guillemets, accolades et espaces injectés.
	if event["cf_ray"] != "abcactionforgedDROP" {
		t.Fatalf("cf_ray = %v, want abcactionforgedDROP (valeur filtrée)", event["cf_ray"])
	}
	if event["cf_country"] != nil {
		t.Fatalf("cf_country = %v, want null (code pays forgé rejeté)", event["cf_country"])
	}
}

// TestSanitizedTokenAndCountryCode verrouille le comportement des primitives
// d'assainissement, y compris les cas limites non couverts par le middleware.
func TestSanitizedTokenAndCountryCode(t *testing.T) {
	if got := sanitizedToken("", maxCFRayLen); got != nil {
		t.Fatalf("sanitizedToken(vide) = %q, want nil", *got)
	}
	if got := sanitizedToken("!!!@@@ \n", maxCFRayLen); got != nil {
		t.Fatalf("sanitizedToken(aucun caractère autorisé) = %q, want nil", *got)
	}

	for _, valid := range []string{"FR", "US", "XX", "T1"} {
		if !isCountryCode(valid) {
			t.Fatalf("isCountryCode(%q) = false, want true", valid)
		}
	}
	for _, invalid := range []string{"", "F", "FRA", "fr", "F1", "00", "9Z", "T2", "F R"} {
		if isCountryCode(invalid) {
			t.Fatalf("isCountryCode(%q) = true, want false", invalid)
		}
	}
}

// Un CF-Ray démesuré (client hors Cloudflare) est tronqué à maxCFRayLen.
func TestMiddlewareCapsOversizedCFRay(t *testing.T) {
	var output bytes.Buffer
	log := NewWithWriter(config.Default().Logging, &output)
	scores, store := newTestScoreManager(t)
	defer store.Close()
	handler := log.Middleware(scores, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "1.2.3.4:1234"
	request.Header.Set("CF-Ray", strings.Repeat("a", 500))

	handler.ServeHTTP(httptest.NewRecorder(), request)

	event := decodeEvent(t, output.String())
	rayVal, _ := event["cf_ray"].(string)
	if len(rayVal) != maxCFRayLen {
		t.Fatalf("cf_ray length = %d, want %d (tronqué)", len(rayVal), maxCFRayLen)
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
