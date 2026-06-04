package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/trust"
)

func TestMiddlewareAllowsConfiguredBurstAndThenRateLimits(t *testing.T) {
	store := memory.New(100)
	t.Cleanup(store.Close)

	cfg := testConfig(100, 100)
	cfg.Trust.BlockThreshold = -1
	middleware := newTestMiddlewareFromConfig(t, store, cfg)
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	middleware.now = func() time.Time { return now }

	handler := middleware.Handler(countingHandler())
	statuses := make([]int, 0, 150)
	for i := 0; i < 150; i++ {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, requestFrom("1.2.3.4:1234"))
		statuses = append(statuses, response.Code)
	}

	okCount := 0
	rateLimitedCount := 0
	for _, status := range statuses {
		switch status {
		case http.StatusNoContent:
			okCount++
		case http.StatusTooManyRequests:
			rateLimitedCount++
		}
	}
	if okCount != 100 {
		t.Fatalf("okCount = %d, want 100", okCount)
	}
	if rateLimitedCount != 50 {
		t.Fatalf("rateLimitedCount = %d, want 50", rateLimitedCount)
	}
}

func TestMiddlewareSetsRetryAfterAndDecrementsScore(t *testing.T) {
	store := memory.New(100)
	t.Cleanup(store.Close)

	middleware := newTestMiddleware(t, store, 1, 1)
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	middleware.now = func() time.Time { return now }
	handler := middleware.Handler(countingHandler())

	handler.ServeHTTP(httptest.NewRecorder(), requestFrom("5.5.5.5:1234"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestFrom("5.5.5.5:1234"))

	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", response.Code)
	}
	if response.Header().Get("Retry-After") == "" {
		t.Fatal("Retry-After header is missing")
	}
	visitor, ok := store.GetVisitor(trust.HashIP("5.5.5.5"))
	if !ok {
		t.Fatal("expected visitor score to be stored")
	}
	if visitor.Score != 40 {
		t.Fatalf("score = %d, want 40", visitor.Score)
	}
}

func TestMiddlewareRecoversAfterRefill(t *testing.T) {
	store := memory.New(100)
	t.Cleanup(store.Close)

	middleware := newTestMiddleware(t, store, 1, 1)
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	middleware.now = func() time.Time { return now }
	handler := middleware.Handler(countingHandler())

	handler.ServeHTTP(httptest.NewRecorder(), requestFrom("1.2.3.4:1234"))
	handler.ServeHTTP(httptest.NewRecorder(), requestFrom("1.2.3.4:1234"))

	now = now.Add(2 * time.Second)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestFrom("1.2.3.4:1234"))

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}

func TestMiddlewareBlocksWhenRateLimitDropsScoreBelowThreshold(t *testing.T) {
	store := memory.New(100)
	t.Cleanup(store.Close)

	middleware := newTestMiddleware(t, store, 1, 1)
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	middleware.now = func() time.Time { return now }
	manager, err := trust.NewScoreManager(store, testConfig(1, 1))
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	manager.Set("12.12.12.12", "example.test", 12)
	handler := middleware.Handler(countingHandler())

	handler.ServeHTTP(httptest.NewRecorder(), requestFrom("12.12.12.12:1234"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestFrom("12.12.12.12:1234"))

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if got := response.Header().Get("X-WAF-Reason"); got != "score_below_block_threshold" {
		t.Fatalf("X-WAF-Reason = %q, want score_below_block_threshold", got)
	}
}

func TestMiddlewareSkipsWhitelistedRequests(t *testing.T) {
	store := memory.New(100)
	t.Cleanup(store.Close)

	middleware := newTestMiddleware(t, store, 1, 1)
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	middleware.now = func() time.Time { return now }
	handler := middleware.Handler(countingHandler())

	for i := 0; i < 10; i++ {
		request := requestFrom("10.0.0.1:1234")
		request.Header.Set("X-WAF-Action", "PASS")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", response.Code)
		}
	}
}

func newTestMiddleware(t *testing.T, store *memory.Store, rate float64, burst int) *Middleware {
	t.Helper()

	return newTestMiddlewareFromConfig(t, store, testConfig(rate, burst))
}

func newTestMiddlewareFromConfig(t *testing.T, store *memory.Store, cfg config.Config) *Middleware {
	t.Helper()

	scoreManager, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	middleware, err := New(store, scoreManager, cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return middleware
}

func testConfig(rate float64, burst int) config.Config {
	cfg := config.Default()
	cfg.Version = "1.0"
	cfg.Server.Listen = ":0"
	cfg.Upstream.Address = "http://example.test"
	cfg.Challenge.Enabled = false
	cfg.Admin.Enabled = false
	cfg.RateLimit.RequestsPerSecond = rate
	cfg.RateLimit.Burst = burst
	return cfg
}

func requestFrom(remoteAddr string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = remoteAddr
	return request
}

func countingHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
}
