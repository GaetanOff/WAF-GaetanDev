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
	metrics := New().WithDomains([]string{"example.test"})
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
	metrics := New().WithDomains([]string{"example.test"})
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

func TestMiddlewareRecordsRiskDecisionMetrics(t *testing.T) {
	metrics := New()
	scores, store := newTestScoreManager(t)
	defer store.Close()
	handler := metrics.Middleware(scores, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-WAF-Risk-Decision", actionBlock)
		r.Header.Set("X-WAF-Risk-Corroborated", "true")
		r.Header.Set("X-WAF-Risk-Verified-Bot", "googlebot")
		r.Header.Set("X-WAF-Challenge-Pass-After-Flag", "true")
		w.Header().Set("X-WAF-Action", actionBlock)
		w.WriteHeader(http.StatusForbidden)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
	request.RemoteAddr = "1.2.3.4:1234"

	handler.ServeHTTP(httptest.NewRecorder(), request)

	body := scrape(t, metrics)
	assertMetricContains(t, body, `waf_decisions_total{tier="BLOCK"} 1`)
	assertMetricContains(t, body, `waf_hard_blocks_total{corroborated="true"} 1`)
	assertMetricContains(t, body, `waf_verified_bot_total{bot="googlebot"} 1`)
	assertMetricContains(t, body, `waf_challenge_pass_after_flag_total 1`)
}

func TestMiddlewareRecordsGlobalPressureGauge(t *testing.T) {
	metrics := New()
	scores, store := newTestScoreManager(t)
	defer store.Close()
	handler := metrics.Middleware(scores, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-WAF-Global-Pressure", "critical")
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
	request.RemoteAddr = "1.2.3.4:1234"

	handler.ServeHTTP(httptest.NewRecorder(), request)

	body := scrape(t, metrics)
	assertMetricContains(t, body, `waf_global_pressure{level="critical"} 1`)
	assertMetricContains(t, body, `waf_global_pressure{level="normal"} 0`)
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

// Sans server.strict_host, le Host est libre : un label domain par Host
// inventé faisait croître la mémoire sans borne. Seuls les hôtes de domains[]
// portent leur propre label.
func TestMiddlewareBoundsTheDomainLabelToDeclaredDomains(t *testing.T) {
	metrics := New().WithDomains([]string{"shop.example.com", "*.example.org"})
	handler := metrics.Middleware(nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-WAF-Action", actionBlock)
		w.Header().Set("X-WAF-Reason", "blacklist_exact")
		w.WriteHeader(http.StatusForbidden)
	}))

	for _, host := range []string{"Shop.Example.com:443", "api.example.org", "example.org", "attack-1.test", "attack-2.test"} {
		request := httptest.NewRequest(http.MethodGet, "http://placeholder/", nil)
		request.Host = host
		request.RemoteAddr = "1.2.3.4:1234"
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}

	body := scrape(t, metrics)
	assertMetricContains(t, body, `waf_requests_total{action="BLOCK",domain="shop.example.com"} 1`)
	assertMetricContains(t, body, `waf_requests_total{action="BLOCK",domain="*.example.org"} 2`)
	assertMetricContains(t, body, `waf_blocked_total{domain="_undeclared",reason="blacklist_exact"} 2`)
	if strings.Contains(body, "attack-") {
		t.Fatalf("an undeclared Host became a label value:\n%s", body)
	}
}

// FR-15 : une réponse servie par le tarpit est comptée TARPIT ; la seule
// classification posée sur la requête (sans déception, elle atteint l'upstream)
// reste PASS.
func TestMiddlewareCountsTarpitOnlyWhenServed(t *testing.T) {
	cases := []struct {
		name       string
		handler    http.HandlerFunc
		wantAction string
	}{
		{
			name: "served by the tarpit",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-WAF-Action", actionTarpit)
				w.WriteHeader(http.StatusOK)
			},
			wantAction: actionTarpit,
		},
		{
			name: "classified but proxied",
			handler: func(w http.ResponseWriter, r *http.Request) {
				r.Header.Set("X-WAF-Action", actionTarpit)
				w.WriteHeader(http.StatusOK)
			},
			wantAction: actionPass,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			metrics := New().WithDomains([]string{"example.test"})
			scores, store := newTestScoreManager(t)
			defer store.Close()
			request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
			request.RemoteAddr = "1.2.3.4:1234"

			metrics.Middleware(scores, tc.handler).ServeHTTP(httptest.NewRecorder(), request)

			assertMetricContains(t, scrape(t, metrics), `waf_requests_total{action="`+tc.wantAction+`",domain="example.test"} 1`)
		})
	}
}

// FR-29 : métriques d'alertes webhook.
func TestAlertMetrics(t *testing.T) {
	metrics := New().WithAlertsPending(func() int { return 3 })

	metrics.AlertSent("block")
	metrics.AlertSent("block")
	metrics.AlertFailed("honeypot")

	body := scrape(t, metrics)
	assertMetricContains(t, body, `waf_alerts_sent_total{trigger="block"} 2`)
	assertMetricContains(t, body, `waf_alerts_failed_total{trigger="honeypot"} 1`)
	assertMetricContains(t, body, `waf_alerts_pending 3`)
}
