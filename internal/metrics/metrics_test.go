package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/trust"
)

func TestMiddlewareRecordsRequestCountersHistogramAndVisitorGauges(t *testing.T) {
	metrics := New()
	scores, store := newTestScoreManager(t)
	defer store.Close()
	handler := metrics.Middleware(scores, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-WAF-Action", actionChallenge)
		r.Header.Set("X-WAF-Reason", "score_below_challenge_threshold")
		w.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
	request.RemoteAddr = "1.2.3.4:1234"
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	body := scrape(t, metrics)
	assertMetricContains(t, body, `waf_requests_total{action="CHALLENGE",domain="example.test"} 1`)
	assertMetricContains(t, body, `waf_challenged_total{domain="example.test",reason="score_below_challenge_threshold"} 1`)
	assertMetricContains(t, body, `waf_active_visitors 1`)
	assertMetricContains(t, body, `waf_visitors_by_state{state="MONITORED"} 1`)
	assertMetricContains(t, body, `waf_request_duration_seconds_bucket{action="CHALLENGE"`)
}

func TestMiddlewareRecordsBlockedCounter(t *testing.T) {
	metrics := New()
	scores, store := newTestScoreManager(t)
	defer store.Close()
	handler := metrics.Middleware(scores, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-WAF-Action", actionBlock)
		w.Header().Set("X-WAF-Reason", "blacklist_exact")
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
	request.RemoteAddr = "1.2.3.4:1234"

	handler.ServeHTTP(httptest.NewRecorder(), request)

	body := scrape(t, metrics)
	assertMetricContains(t, body, `waf_requests_total{action="BLOCK",domain="example.test"} 1`)
	assertMetricContains(t, body, `waf_blocked_total{domain="example.test",reason="blacklist_exact"} 1`)
}

func scrape(t *testing.T, metrics *Metrics) string {
	t.Helper()

	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/waf/metrics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", response.Code)
	}
	return response.Body.String()
}

func assertMetricContains(t *testing.T, body string, expected string) {
	t.Helper()

	if !strings.Contains(body, expected) {
		t.Fatalf("metrics output missing %q:\n%s", expected, body)
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
