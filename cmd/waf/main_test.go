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

	routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
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
	routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	routes(cfg, newTestRules(t, []string{"172.16.0.1"}, []string{"172.16.0.1"}, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("proxy should not be called")
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestFromPath("198.51.100.10:443", "/.env"))

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestRoutesAppliesGlobalDegradedModeBeforeChallenge(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.AntiDDoS.GlobalRequestsPerSecond = 1
	cfg.AntiDDoS.GlobalWindow = "1s"
	cfg.AntiDDoS.RetryAfterSeconds = 5

	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoSFromConfig(t, cfg), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("proxy should not be called")
	}))

	handler.ServeHTTP(httptest.NewRecorder(), requestFrom("198.51.100.10:443"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestFrom("198.51.100.11:443"))

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
	if response.Header().Get("Retry-After") != "5" {
		t.Fatalf("Retry-After = %q, want 5", response.Header().Get("Retry-After"))
	}
	if response.Header().Get("X-WAF-Reason") != "global_rate_exceeded" {
		t.Fatalf("X-WAF-Reason = %q, want global_rate_exceeded", response.Header().Get("X-WAF-Reason"))
	}
}

func TestRoutesExposesPrometheusMetricsEndpoint(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.Challenge.Enabled = false
	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func TestRoutesAppliesRiskDecisionBeforeProxy(t *testing.T) {
	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.RateLimit.Enabled = false
	cfg.Challenge.Enabled = false
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
	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), riskMiddleware, newTestChallenge(t, cfg), scoreManager, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("proxy should not be called")
	}))
	request := requestFrom("198.51.100.10:443")
	// UA navigateur propre : l'adaptateur antibot ne publie alors aucun signal
	// fingerprint et ne surcharge pas les familles synthétiques de ce test.
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	request.Header.Set("Accept-Language", "en-US")
	request.Header.Set("Accept-Encoding", "gzip")
	request.Header.Set("X-WAF-Risk-Behavioral", "100")
	request.Header.Set("X-WAF-Risk-TLS", "100")
	request.Header.Set("X-WAF-Risk-Fingerprint", "100")
	request.Header.Set("X-WAF-Risk-Integrity", "100")
	request.Header.Set("X-WAF-Risk-Rate", "100")
	request.Header.Set("X-WAF-Risk-Geo", "100")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if response.Header().Get("X-WAF-Reason") != "risk_heuristic" {
		t.Fatalf("X-WAF-Reason = %q, want risk_heuristic", response.Header().Get("X-WAF-Reason"))
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
	return antibot.New(antibot.NewRules(cfg), manager)
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
