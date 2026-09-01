package main

import (
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gaetandev/waf/internal/config"
	waflogger "github.com/gaetandev/waf/internal/logger"
	wafmetrics "github.com/gaetandev/waf/internal/metrics"
	"github.com/gaetandev/waf/internal/middleware/access"
	"github.com/gaetandev/waf/internal/middleware/antibot"
	"github.com/gaetandev/waf/internal/middleware/antiddos"
	"github.com/gaetandev/waf/internal/middleware/challenge"
	"github.com/gaetandev/waf/internal/middleware/ratelimit"
	"github.com/gaetandev/waf/internal/risk"
	"github.com/gaetandev/waf/internal/storage/memory"
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
