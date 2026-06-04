package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/middleware/access"
	"github.com/gaetandev/waf/internal/middleware/antibot"
	"github.com/gaetandev/waf/internal/middleware/ratelimit"
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

	routes(cfg, newTestRules(t, nil, nil, nil), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), newTestScoreManager(t, cfg), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
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

	routes(cfg, newTestRules(t, nil, nil, nil), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), newTestScoreManager(t, cfg), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	routes(cfg, newTestRules(t, []string{"172.16.0.1"}, []string{"172.16.0.1"}, nil), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), newTestScoreManager(t, cfg), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), newTestScoreManager(t, cfg), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), newTestScoreManager(t, cfg), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("proxy should not be called")
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestFromPath("198.51.100.10:443", "/.env"))

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
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
