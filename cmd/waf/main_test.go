package main

import (
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
	waflogger "github.com/gaetandev/waf/internal/logger"
	wafmetrics "github.com/gaetandev/waf/internal/metrics"
	"github.com/gaetandev/waf/internal/middleware/access"
	"github.com/gaetandev/waf/internal/middleware/antibot"
	"github.com/gaetandev/waf/internal/middleware/antiddos"
	"github.com/gaetandev/waf/internal/middleware/challenge"
	"github.com/gaetandev/waf/internal/middleware/ratelimit"
	"github.com/gaetandev/waf/internal/origin"
	"github.com/gaetandev/waf/internal/risk"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/tlsfp"
	"github.com/gaetandev/waf/internal/trust"
)

func TestRoutesRejectsForgedCloudflareHeaderWhenTrusted(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = true

	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "203.0.113.10:443"
	request.Header.Set("CF-Connecting-IP", "198.51.100.25")
	response := httptest.NewRecorder()

	routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("proxy should not be called")
	})).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
}

func TestRoutesSkipsCloudflareValidationWhenNotTrusted(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false

	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "203.0.113.10:443"
	request.Header.Set("CF-Connecting-IP", "198.51.100.25")
	response := httptest.NewRecorder()

	cfg.Challenge.Enabled = false
	routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}

func TestRoutesAppliesWhitelistBeforeBlacklist(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false

	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "172.16.0.1:443"
	response := httptest.NewRecorder()

	routes(cfg, newTestRules(t, []string{"172.16.0.1"}, []string{"172.16.0.1"}, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}

func TestRoutesAppliesRateLimitAfterAccessRules(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.RateLimit.RequestsPerSecond = 1
	cfg.RateLimit.Burst = 1

	cfg.Challenge.Enabled = false
	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), requestFrom("198.51.100.10:443"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestFrom("198.51.100.10:443"))

	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", response.Code)
	}
}

func TestRoutesAppliesAntiBotHoneypot(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.RateLimit.Enabled = false
	cfg.Challenge.Enabled = false
	cfg.RiskEngine.Tiers.Tarpit = 70
	cfg.RiskEngine.Tiers.Block = 75

	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("proxy should not be called")
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestFromPath("198.51.100.10:443", "/.env"))

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestRoutesAppliesGlobalPressureBeforeChallengeWithout503(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.AntiDDoS.GlobalRequestsPerSecond = 1
	cfg.AntiDDoS.GlobalWindow = "1s"

	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoSFromConfig(t, cfg), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("proxy should not be called")
	}))

	handler.ServeHTTP(httptest.NewRecorder(), requestFrom("198.51.100.10:443"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestFrom("198.51.100.11:443"))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 challenge", response.Code)
	}
	if response.Header().Get("Retry-After") != "" {
		t.Fatalf("Retry-After = %q, want empty", response.Header().Get("Retry-After"))
	}
	if response.Header().Get("X-WAF-Reason") != "" {
		t.Fatalf("X-WAF-Reason = %q, want empty", response.Header().Get("X-WAF-Reason"))
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want challenge HTML", contentType)
	}
}

// FR-06 : la chaîne monte le challenge dès qu'un domaine l'active, et la
// décision par requête suit l'hôte — pas le seul réglage global.
func TestRoutesAppliesPerDomainChallengeOverride(t *testing.T) {
	challengeOff, challengeOn := false, true
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.Challenge.Enabled = false // global éteint : seul le domaine l'active
	cfg.Domains = []config.DomainConfig{
		{Host: "boxaria.fr", Upstream: "http://10.0.0.1:80", ChallengeEnabled: &challengeOn},
		{Host: "api.boxaria.fr", Upstream: "http://10.0.0.2:80", ChallengeEnabled: &challengeOff},
	}

	tests := []struct {
		host          string
		wantChallenge bool
	}{
		{host: "boxaria.fr", wantChallenge: true},
		{host: "api.boxaria.fr", wantChallenge: false},
		{host: "autre.test", wantChallenge: false}, // hôte non listé : global éteint
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			proxied := false
			handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				proxied = true
				w.WriteHeader(http.StatusNoContent)
			}))

			request := requestFrom("198.51.100.10:443")
			request.Host = tt.host
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			served := response.Header().Get("Content-Type") == "text/html; charset=utf-8"
			if served != tt.wantChallenge {
				t.Fatalf("challenge served = %v, want %v (status %d)", served, tt.wantChallenge, response.Code)
			}
			if proxied == tt.wantChallenge {
				t.Fatalf("proxied = %v, want %v", proxied, !tt.wantChallenge)
			}
		})
	}
}

func TestRoutesExposesPrometheusMetricsEndpoint(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.Challenge.Enabled = false
	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()

	handler.ServeHTTP(httptest.NewRecorder(), requestFrom("198.51.100.10:443"))
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://example.test/waf/metrics", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if !strings.Contains(response.Body.String(), "waf_requests_total") {
		t.Fatalf("metrics endpoint missing waf_requests_total:\n%s", response.Body.String())
	}
}

// riskFamilyDetector simule les détecteurs de production (intégrité, geo, tlsfp,
// behavioral, rate…) qui publient leurs contributions via les en-têtes
// X-WAF-Risk-* depuis l'intérieur du pipeline. Injecter ces en-têtes depuis la
// requête cliente ne fonctionne plus : le middleware ingress supprime tout
// X-WAF-* fourni par le client (sinon X-WAF-Action: PASS contournerait le WAF).
func riskFamilyDetector(families map[string]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for name, value := range families {
				r.Header.Set(name, value)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func TestRoutesAppliesRiskDecisionBeforeProxy(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.RateLimit.Enabled = false
	cfg.Challenge.Enabled = false
	cfg.RiskEngine.ShadowMode = false // ce test vérifie l'enforcement
	cfg.RiskEngine.Tiers.Tarpit = 70
	cfg.RiskEngine.Tiers.Block = 75
	store := memory.New(100)
	defer store.Close()
	scoreManager, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	riskMiddleware, err := risk.NewMiddleware(store, scoreManager, cfg)
	if err != nil {
		t.Fatalf("risk.NewMiddleware() error = %v", err)
	}
	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), riskMiddleware, newTestChallenge(t, cfg), scoreManager, []func(http.Handler) http.Handler{riskFamilyDetector(map[string]string{
		"X-WAF-Risk-Behavioral":  "100",
		"X-WAF-Risk-TLS":         "100",
		"X-WAF-Risk-Fingerprint": "100",
		"X-WAF-Risk-Integrity":   "100",
		"X-WAF-Risk-Rate":        "100",
		"X-WAF-Risk-Geo":         "100",
	})}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("proxy should not be called")
	}))
	request := requestFrom("198.51.100.10:443")
	// UA navigateur propre : l'adaptateur antibot ne publie alors aucun signal
	// fingerprint et ne surcharge pas les familles synthétiques de ce test.
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	request.Header.Set("Accept-Language", "en-US")
	request.Header.Set("Accept-Encoding", "gzip")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if response.Header().Get("X-WAF-Reason") != "risk_heuristic" {
		t.Fatalf("X-WAF-Reason = %q, want risk_heuristic", response.Header().Get("X-WAF-Reason"))
	}
}

func TestRoutesRiskEngineShadowByDefault(t *testing.T) {
	cfg := config.Default() // shadow_mode = true par défaut (calibration NFR-15)
	cfg.Cloudflare.Trusted = false
	cfg.RateLimit.Enabled = false
	cfg.Challenge.Enabled = false
	store := memory.New(100)
	defer store.Close()
	scoreManager, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	riskMiddleware, err := risk.NewMiddleware(store, scoreManager, cfg)
	if err != nil {
		t.Fatalf("risk.NewMiddleware() error = %v", err)
	}
	// Familles synthétiques élevées, publiées depuis l'intérieur du pipeline
	// comme le font les détecteurs de production. Sans shadow, la fusion rend
	// une décision de mitigation (THROTTLE à 58 aujourd'hui) : c'est ce que
	// l'assertion sur X-WAF-Risk-Decision vérifie, sinon « le proxy est appelé »
	// serait vrai trivialement.
	proxyCalled := false
	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), riskMiddleware, newTestChallenge(t, cfg), scoreManager, []func(http.Handler) http.Handler{riskFamilyDetector(map[string]string{
		"X-WAF-Risk-Behavioral": "100",
		"X-WAF-Risk-TLS":        "100",
		"X-WAF-Risk-Integrity":  "100",
		"X-WAF-Risk-Geo":        "100",
	})}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))
	request := requestFrom("198.51.100.10:443")
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if !proxyCalled || response.Code != http.StatusNoContent {
		t.Fatalf("shadow mode must not enforce: proxyCalled=%v status=%d", proxyCalled, response.Code)
	}
	if request.Header.Get("X-WAF-Risk-Shadow-Mode") != "true" {
		t.Fatalf("X-WAF-Risk-Shadow-Mode = %q, want true", request.Header.Get("X-WAF-Risk-Shadow-Mode"))
	}
	if decision := request.Header.Get("X-WAF-Risk-Decision"); decision == "" || decision == "ALLOW" {
		t.Fatalf("X-WAF-Risk-Decision = %q, want une décision de mitigation : sans elle le shadow n'est pas testé", decision)
	}
}

func TestRoutesCorroboratedBlockFromRealSignals(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.Challenge.Enabled = false
	cfg.RiskEngine.ShadowMode = false
	cfg.RiskEngine.BlockMinConfidence = 0.2
	cfg.RiskEngine.Tiers = config.RiskTiers{Observe: 2, Throttle: 5, Challenge: 8, Tarpit: 12, Block: 20}
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.RequestsPerSecond = 1
	cfg.RateLimit.Burst = 1

	store := memory.New(100)
	defer store.Close()
	scoreManager, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	// Visiteur à faible confiance → famille reputation élevée (95).
	scoreManager.Set("198.51.100.10", "example.test", 5)
	riskMiddleware, err := risk.NewMiddleware(store, scoreManager, cfg)
	if err != nil {
		t.Fatalf("risk.NewMiddleware() error = %v", err)
	}
	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), riskMiddleware, newTestChallenge(t, cfg), scoreManager, nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("corroborated block must not reach the proxy")
	}))
	request := requestFrom("198.51.100.10:443")
	// UA propre : seules reputation (réelle) + rate (réelle, bucket vidé) corroborent.
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	request.Header.Set("Accept-Language", "en-US")
	request.Header.Set("Accept-Encoding", "gzip")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (corroborated block)", response.Code)
	}
	if request.Header.Get("X-WAF-Risk-Corroborated") != "true" {
		t.Fatalf("X-WAF-Risk-Corroborated = %q, want true", request.Header.Get("X-WAF-Risk-Corroborated"))
	}
}

func TestRunHealthCheck(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthy.Close()
	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unhealthy.Close()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{name: "healthy", url: healthy.URL, wantErr: false},
		{name: "unhealthy status", url: unhealthy.URL, wantErr: true},
		{name: "unreachable", url: "http://127.0.0.1:0/waf/health", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runHealthCheck(tt.url)
			if (err != nil) != tt.wantErr {
				t.Fatalf("runHealthCheck() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// FR-30 : les en-têtes X-WAF-* sont de l'état interne du pipeline. Un client qui
// posait lui-même X-WAF-Action: PASS court-circuitait le challenge, le rate
// limiting, l'analyse d'intégrité, le threat intel et le moteur de règles — un
// contournement complet du WAF en un seul en-tête. Le premier cas est le témoin :
// sans lui, le test passerait même si le challenge ne se déclenchait jamais.
func TestRoutesIgnoresClientSuppliedWAFHeaders(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.Challenge.Enabled = true

	tests := []struct {
		name   string
		forged map[string]string
	}{
		{name: "temoin sans en-tete forge"},
		{name: "action PASS", forged: map[string]string{"X-WAF-Action": "PASS"}},
		{name: "action PASS en minuscules", forged: map[string]string{"x-waf-action": "PASS"}},
		{name: "score de confiance", forged: map[string]string{"X-WAF-Score": "100", "X-WAF-State": "TRUSTED"}},
		{name: "familles de risque", forged: map[string]string{"X-WAF-Risk-Behavioral": "0", "X-WAF-Risk-Decision": "ALLOW"}},
		{name: "jeton d'origine", forged: map[string]string{"X-WAF-Origin-Token": "forge"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxied := false
			handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				proxied = true
				w.WriteHeader(http.StatusNoContent)
			}))

			request := requestFrom("198.51.100.10:443")
			for name, value := range tt.forged {
				request.Header.Set(name, value)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if proxied {
				t.Fatalf("upstream atteint (status %d) : en-têtes %v honorés", response.Code, tt.forged)
			}
			if got := response.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
				t.Fatalf("Content-Type = %q, want la page de challenge (status %d)", got, response.Code)
			}
		})
	}
}

// FR-19 × FR-30 : l'assainissement d'ingress supprime tout X-WAF-* fourni par le
// client, mais /waf/origin/verify est appelé par l'upstream qui lui retransmet le
// X-WAF-Origin-Token reçu. Sans la capture en amont de l'assainisseur, l'oracle
// répond 401 à tout token, valide compris — la vérification FR-19 est inopérante.
func TestRoutesOriginVerifyReadsTheRetransmittedToken(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.Challenge.Enabled = false
	cfg.OriginProtection.Enabled = true
	cfg.OriginProtection.Secret = secret

	tests := []struct {
		name       string
		token      string
		wantStatus int
	}{
		{name: "token valide", token: origin.NewSigner(secret).Token("example.test"), wantStatus: http.StatusOK},
		{name: "token forge", token: "forge", wantStatus: http.StatusUnauthorized},
		{name: "aucun token", token: "", wantStatus: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("proxy should not be called for /waf/origin/verify")
			}))

			request := httptest.NewRequest(http.MethodGet, "http://example.test/waf/origin/verify", nil)
			request.RemoteAddr = "198.51.100.10:443"
			if tt.token != "" {
				request.Header.Set(origin.HeaderToken, tt.token)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", response.Code, tt.wantStatus, response.Body.String())
			}
		})
	}
}

func newTestRules(t *testing.T, whitelist []string, blacklist []string, userAgents []string) *access.RuleSet {
	t.Helper()

	rules, err := access.NewRuleSet(whitelist, blacklist, userAgents)
	if err != nil {
		t.Fatalf("NewRuleSet() error = %v", err)
	}
	return rules
}

func newTestLogger() waflogger.Logger {
	return waflogger.NewWithWriter(config.Default().Logging, io.Discard)
}

func newTestMetrics() *wafmetrics.Metrics {
	return wafmetrics.New()
}

func newTestRateLimiter(t *testing.T, cfg config.Config) *ratelimit.Middleware {
	t.Helper()

	store := memory.New(100)
	t.Cleanup(store.Close)
	cfg.Version = "1.0"
	cfg.Server.Listen = ":0"
	cfg.Upstream.Address = "http://example.test"
	cfg.Challenge.Enabled = false
	cfg.Admin.Enabled = false

	scoreManager, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	middleware, err := ratelimit.New(store, scoreManager, cfg)
	if err != nil {
		t.Fatalf("ratelimit.New() error = %v", err)
	}
	return middleware
}

func newTestAntiDDoS(t *testing.T) antiddos.Middleware {
	t.Helper()

	store := memory.New(100)
	t.Cleanup(store.Close)
	return antiddos.New(antiddos.NewCircuitBreaker(store, antiddos.DefaultViolationThreshold, antiddos.DefaultOpenDuration), nil, antiddos.DefaultRetryAfterSeconds)
}

func newTestAntiDDoSFromConfig(t *testing.T, cfg config.Config) antiddos.Middleware {
	t.Helper()

	store := memory.New(100)
	t.Cleanup(store.Close)
	middleware, err := antiddos.NewFromConfig(store, cfg)
	if err != nil {
		t.Fatalf("antiddos.NewFromConfig() error = %v", err)
	}
	return middleware
}

func newTestScoreManager(t *testing.T, cfg config.Config) *trust.ScoreManager {
	t.Helper()

	store := memory.New(100)
	t.Cleanup(store.Close)
	cfg.Version = "1.0"
	cfg.Server.Listen = ":0"
	cfg.Upstream.Address = "http://example.test"
	cfg.Challenge.Enabled = false
	cfg.Admin.Enabled = false

	manager, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	return manager
}

func requestFrom(remoteAddr string) *http.Request {
	return requestFromPath(remoteAddr, "/")
}

func requestFromPath(remoteAddr string, path string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.URL.Path = path
	request.RemoteAddr = remoteAddr
	// Simule une navigation de navigateur : le challenge JS ne cible que ce cas.
	request.Header.Set("Accept", "text/html")
	return request
}

func newTestAntiBot(t *testing.T, cfg config.Config) antibot.Middleware {
	t.Helper()

	store := memory.New(100)
	t.Cleanup(store.Close)
	cfg.Version = "1.0"
	cfg.Server.Listen = ":0"
	cfg.Upstream.Address = "http://example.test"
	cfg.Challenge.Enabled = false
	cfg.Admin.Enabled = false

	manager, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	return antibot.New(antibot.NewRules(cfg), manager, cfg.RiskEngine.ShadowMode)
}

func newTestChallenge(t *testing.T, cfg config.Config) challenge.Middleware {
	t.Helper()

	store := memory.New(100)
	t.Cleanup(store.Close)
	cfg.Version = "1.0"
	cfg.Server.Listen = ":0"
	cfg.Upstream.Address = "http://example.test"
	cfg.Challenge.SecretKey = "0123456789abcdef0123456789abcdef"
	cfg.Admin.Enabled = false

	manager, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	pageTemplate := template.Must(template.New("challenge").Parse(`{{.Token}} {{.Difficulty}} {{.RedirectURL}}`))
	middleware, err := challenge.NewMiddlewareFromTemplate(cfg, manager, pageTemplate)
	if err != nil {
		t.Fatalf("challenge.NewMiddlewareFromTemplate() error = %v", err)
	}
	return middleware
}

// FR-34 : une décision CHALLENGE du moteur de risque sert la page de challenge.
// Avant l'Enforcer, la requête atteignait l'upstream avec X-WAF-Action=CHALLENGE.
func TestRoutesEnforcesRiskChallengeDecision(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.RateLimit.Enabled = false
	cfg.RiskEngine.ShadowMode = false
	cfg.RiskEngine.Tiers = config.RiskTiers{Observe: 1, Throttle: 2, Challenge: 3, Tarpit: 99, Block: 100}
	store := memory.New(100)
	defer store.Close()
	scoreManager, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	riskMiddleware, err := risk.NewMiddleware(store, scoreManager, cfg)
	if err != nil {
		t.Fatalf("risk.NewMiddleware() error = %v", err)
	}
	challengeMiddleware := newTestChallenge(t, cfg)
	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), riskMiddleware, challengeMiddleware, scoreManager, []func(http.Handler) http.Handler{riskFamilyDetector(map[string]string{
		"X-WAF-Risk-Integrity": "100",
	})}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("proxy reached with X-WAF-Action=%q: CHALLENGE decision not enforced", r.Header.Get("X-WAF-Action"))
	}))
	request := requestFrom("198.51.100.10:443")
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	request.Header.Set("Accept-Language", "en-US")
	request.Header.Set("Accept-Encoding", "gzip")
	// Clearance valide : le premier middleware challenge laisse passer, seul
	// l'Enforcer, en aval du moteur de risque, peut encore servir la page.
	cookie, err := challenge.Issue(cfg.Challenge.CookieName, "0123456789abcdef0123456789abcdef", "198.51.100.10", "example.test", strings.Repeat("a", 64), 75, time.Hour)
	if err != nil {
		t.Fatalf("challenge.Issue() error = %v", err)
	}
	request.AddCookie(&cookie)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("status = %d content-type = %q, want the challenge page", response.Code, response.Header().Get("Content-Type"))
	}
	if decision := request.Header.Get("X-WAF-Risk-Decision"); decision != "CHALLENGE" {
		t.Fatalf("X-WAF-Risk-Decision = %q, want CHALLENGE: the test must exercise the risk decision", decision)
	}
}

// FR-37 : après un challenge réussi, la preuve humaine (challenge + fingerprint
// du cookie) ramène la décision à ALLOW — l'Enforcer ne boucle pas.
func TestRoutesHumanCreditStopsRechallengeLoop(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.RateLimit.Enabled = false
	cfg.RiskEngine.ShadowMode = false
	cfg.RiskEngine.Tiers = config.RiskTiers{Observe: 1, Throttle: 2, Challenge: 3, Tarpit: 99, Block: 100}
	store := memory.New(100)
	defer store.Close()
	scoreManager, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	riskMiddleware, err := risk.NewMiddleware(store, scoreManager, cfg)
	if err != nil {
		t.Fatalf("risk.NewMiddleware() error = %v", err)
	}
	fpHash := strings.Repeat("c", 64)
	scoreManager.Apply("198.51.100.10", "example.test", trust.DeltaChallengePassed)
	riskMiddleware.GrantChallengePass("198.51.100.10", "example.test", fpHash)

	proxied := false
	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), riskMiddleware, newTestChallenge(t, cfg), scoreManager, []func(http.Handler) http.Handler{riskFamilyDetector(map[string]string{
		"X-WAF-Risk-Integrity": "100",
	})}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied = true
		w.WriteHeader(http.StatusNoContent)
	}))
	request := requestFrom("198.51.100.10:443")
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	request.Header.Set("Accept-Language", "en-US")
	request.Header.Set("Accept-Encoding", "gzip")
	cookie, err := challenge.Issue(cfg.Challenge.CookieName, "0123456789abcdef0123456789abcdef", "198.51.100.10", "example.test", fpHash, 75, time.Hour)
	if err != nil {
		t.Fatalf("challenge.Issue() error = %v", err)
	}
	request.AddCookie(&cookie)

	handler.ServeHTTP(httptest.NewRecorder(), request)

	if !proxied {
		t.Fatalf("proven human re-challenged: X-WAF-Risk-Decision = %q", request.Header.Get("X-WAF-Risk-Decision"))
	}
}

// whitelist_user_agents n'est pas un bypass : « User-Agent: Googlebot » se
// forge. Il exempte du challenge proactif, pas du rate limit (ni du reste).
func TestRoutesWhitelistedUserAgentIsNotABypass(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.RateLimit.RequestsPerSecond = 1
	cfg.RateLimit.Burst = 1
	proxied := 0
	handler := routes(cfg, newTestRules(t, nil, nil, []string{"Googlebot"}), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied++
		w.WriteHeader(http.StatusNoContent)
	}))
	crawler := func() *http.Request {
		request := requestFrom("198.51.100.10:443")
		request.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
		return request
	}

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, crawler())
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, crawler())

	if first.Code != http.StatusNoContent || proxied != 1 {
		t.Fatalf("first request: status = %d proxied = %d, want 204 without challenge", first.Code, proxied)
	}
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: status = %d, want 429 — the User-Agent whitelist must not skip the rate limit", second.Code)
	}
}

// FR-11 / FR-35 : sans moteur de risque, un JA3 blacklisté bloque quand même.
// Le middleware de score, seul décideur dans ce cas, ignorait le déclencheur.
func TestRoutesDeterministicTriggerBlocksWithoutRiskEngine(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.RiskEngine.Enabled = false
	cfg.Challenge.Enabled = false
	const blacklisted = "3b5074b1b5d032e5620f69f9159a1b97"
	ja3 := tlsfp.NewMiddleware(config.TLSFingerprint{Enabled: true, JA3Header: "X-Client-JA3", JA3Blacklist: []string{blacklisted}}, 100)
	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), []func(http.Handler) http.Handler{ja3.Handler}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("a blacklisted JA3 must not reach the upstream")
	}))
	request := requestFrom("198.51.100.10:443")
	request.Header.Set("User-Agent", "Mozilla/5.0")
	request.Header.Set("Accept-Language", "fr")
	request.Header.Set("Accept-Encoding", "gzip")
	request.Header.Set("X-Client-JA3", blacklisted)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if got := response.Header().Get("X-WAF-Reason"); got != "ja3_blacklisted" {
		t.Fatalf("X-WAF-Reason = %q, want ja3_blacklisted", got)
	}
}

// FR-23 / FR-02 : la borne slowloris par IP porte sur le visiteur
// (CF-Connecting-IP), pas sur le point de présence Cloudflare qui relaie
// plusieurs visiteurs légitimes sur la même adresse source.
func TestRoutesSlowlorisCountsTheCloudflareVisitorNotThePoP(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = true
	cfg.Challenge.Enabled = false
	cfg.Slowloris.Enabled = true
	cfg.Slowloris.MaxConnsPerIP = 1
	release := make(chan struct{})
	inFlight := make(chan struct{})
	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("CF-Connecting-IP") == "198.51.100.1" {
			close(inFlight)
			<-release
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	viaPoP := func(visitor string) *http.Request {
		request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
		request.RemoteAddr = "173.245.48.10:443" // plage Cloudflare
		request.Header.Set("CF-Connecting-IP", visitor)
		return request
	}
	first := make(chan int)
	go func() {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, viaPoP("198.51.100.1"))
		first <- response.Code
	}()
	<-inFlight

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, viaPoP("198.51.100.2"))
	close(release)

	if second.Code != http.StatusNoContent {
		t.Fatalf("second visitor behind the same PoP: status = %d, want 204", second.Code)
	}
	if code := <-first; code != http.StatusNoContent {
		t.Fatalf("first visitor: status = %d, want 204", code)
	}
}

// FR-09 / FR-23 / FR-30 / ADR-020 : les refus d'enveloppe sont comptés dans
// Prometheus et journalisés comme toute décision du WAF. Montés au-dessus du
// journal et des métriques, ils étaient invisibles.
func TestRoutesEnvelopeRejectionsAreObserved(t *testing.T) {
	cases := []struct {
		name       string
		configure  func(*config.Config)
		request    func() *http.Request
		wantCode   int
		wantAction string
		wantReason string
	}{
		{
			name: "strict host",
			configure: func(cfg *config.Config) {
				cfg.Server.StrictHost = true
				cfg.Domains = []config.DomainConfig{{Host: "boxaria.fr", Upstream: "http://10.0.0.1"}}
			},
			request: func() *http.Request {
				request := requestFrom("203.0.113.10:1234")
				request.Host = "undeclared.test"
				return request
			},
			wantCode:   http.StatusBadRequest,
			wantAction: "BLOCK",
			wantReason: "host_not_declared",
		},
		{
			name: "verify flood",
			configure: func(cfg *config.Config) {
				cfg.SelfProtection.Enabled = true
				cfg.SelfProtection.VerifyMaxPerMinute = 1
			},
			request: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "http://example.test/waf/verify", strings.NewReader(`{}`))
			},
			wantCode:   http.StatusTooManyRequests,
			wantAction: "RATE_LIMIT",
			wantReason: "self_protect_flood",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Cloudflare.Trusted = false
			cfg.Challenge.Enabled = false
			tc.configure(&cfg)
			events := &eventLog{}
			logger := newTestLogger()
			logger.Recorder = events
			metrics := newTestMetrics()
			handler := routes(cfg, newTestRules(t, nil, nil, nil), logger, metrics, newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))

			var response *httptest.ResponseRecorder
			for range 2 { // la deuxième requête franchit la borne de /waf/verify
				response = httptest.NewRecorder()
				handler.ServeHTTP(response, tc.request())
			}

			if response.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", response.Code, tc.wantCode)
			}
			assertObserved(t, handler, events, tc.wantAction, tc.wantReason)
		})
	}
}

func TestRoutesSlowlorisRejectionIsObserved(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.Challenge.Enabled = false
	cfg.Slowloris.Enabled = true
	cfg.Slowloris.MaxConnsPerIP = 1
	events := &eventLog{}
	logger := newTestLogger()
	logger.Recorder = events
	release := make(chan struct{})
	inFlight := make(chan struct{})
	handler := routes(cfg, newTestRules(t, nil, nil, nil), logger, newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(inFlight)
			<-release
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(httptest.NewRecorder(), requestFromPath("198.51.100.1:1234", "/slow"))
		close(done)
	}()
	<-inFlight

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, requestFrom("198.51.100.1:1234"))
	close(release)
	<-done

	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", second.Code)
	}
	assertObserved(t, handler, events, "RATE_LIMIT", "too_many_connections_per_ip")
}

// assertObserved vérifie que le refus figure dans waf_requests_total et dans
// le journal de sécurité (qui alimente aussi GET /waf/admin/events).
func assertObserved(t *testing.T, handler http.Handler, events *eventLog, action string, reason string) {
	t.Helper()
	if !events.has(action, reason) {
		t.Fatalf("no security event with action=%s reason=%s in %+v", action, reason, events.events)
	}
	scrape := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://example.test/waf/metrics", nil)
	request.Host = "boxaria.fr"
	handler.ServeHTTP(scrape, request)
	if want := `waf_requests_total{action="` + action + `"`; !strings.Contains(scrape.Body.String(), want) {
		t.Fatalf("metrics do not count the rejection: missing %s", want)
	}
}

type eventLog struct {
	mu     sync.Mutex
	events []waflogger.SecurityEvent
}

func (l *eventLog) RecordSecurityEvent(event waflogger.SecurityEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *eventLog) has(action string, reason string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, event := range l.events {
		if event.Action == action && event.Reason == reason {
			return true
		}
	}
	return false
}

// ADR-020 option 1C, monté dans la chaîne réelle : le Host non déclaré n'atteint
// pas l'upstream, la sonde de santé par IP reste servie.
func TestRoutesStrictHostRejectsUndeclaredHosts(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.Challenge.Enabled = false
	cfg.Server.StrictHost = true
	cfg.Domains = []config.DomainConfig{{Host: "boxaria.fr", Upstream: "http://10.0.0.1"}}
	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "boxaria.fr" {
			t.Fatalf("undeclared host %q reached the upstream", r.Host)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	send := func(host string, path string) int {
		request := httptest.NewRequest(http.MethodGet, "http://placeholder"+path, nil)
		request.Host = host
		request.RemoteAddr = "203.0.113.10:1234"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}

	if code := send("peu-importe.test", "/"); code != http.StatusBadRequest {
		t.Fatalf("undeclared host: status = %d, want 400", code)
	}
	if code := send("boxaria.fr", "/"); code != http.StatusNoContent {
		t.Fatalf("declared host: status = %d, want 204", code)
	}
	if code := send("10.0.0.5:8080", "/waf/health"); code != http.StatusOK {
		t.Fatalf("health probe by IP: status = %d, want 200", code)
	}
	if code := send("10.0.0.5:8080", "/waf/metrics"); code != http.StatusBadRequest {
		t.Fatalf("metrics by IP: status = %d, want 400 — /waf/metrics is not exempt", code)
	}
}

// Le Host est normalisé comme pour le routage avant d'être comparé aux
// domaines : la casse et le port ne font plus refuser un domaine déclaré.
func TestRedirectToHTTPSNormalizesTheHost(t *testing.T) {
	handler := redirectToHTTPS([]config.DomainConfig{{Host: "Example.com"}, {Host: "*.boxaria.fr"}})
	cases := []struct {
		host     string
		wantCode int
		wantURL  string
	}{
		{host: "example.com", wantCode: http.StatusMovedPermanently, wantURL: "https://example.com/path?q=1"},
		{host: "EXAMPLE.com:80", wantCode: http.StatusMovedPermanently, wantURL: "https://example.com/path?q=1"},
		{host: "www.Boxaria.fr:8080", wantCode: http.StatusMovedPermanently, wantURL: "https://www.boxaria.fr/path?q=1"},
		{host: "evil.test", wantCode: http.StatusBadRequest},
		{host: "[::1]:8080", wantCode: http.StatusBadRequest},
	}
	for _, tc := range cases {
		request := httptest.NewRequest(http.MethodGet, "http://placeholder/path?q=1", nil)
		request.Host = tc.host
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		if response.Code != tc.wantCode {
			t.Fatalf("%s: status = %d, want %d", tc.host, response.Code, tc.wantCode)
		}
		if got := response.Header().Get("Location"); got != tc.wantURL {
			t.Fatalf("%s: Location = %q, want %q", tc.host, got, tc.wantURL)
		}
	}
}

// FR-26 : un domains[].upstream distinct de upstream.address est inerte sous
// upstream_pool ; il est signalé au démarrage.
func TestPoolShadowedDomains(t *testing.T) {
	cfg := config.Default()
	cfg.Upstream.Address = "http://10.0.0.1"
	cfg.Domains = []config.DomainConfig{
		{Host: "www.example.com", Upstream: "http://10.0.0.1"},
		{Host: "api.example.com", Upstream: "http://10.0.0.2"},
	}
	if got := poolShadowedDomains(cfg); got != nil {
		t.Fatalf("pool disabled: got %v, want none", got)
	}
	cfg.UpstreamPool.Enabled = true
	got := poolShadowedDomains(cfg)
	if len(got) != 1 || got[0] != "api.example.com" {
		t.Fatalf("got %v, want [api.example.com]", got)
	}
}
