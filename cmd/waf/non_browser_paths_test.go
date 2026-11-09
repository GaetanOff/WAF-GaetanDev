package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gaetandev/waf/internal/config"
)

// Scénarios de specs/features/non-browser-paths.feature (FR-41) sur le
// pipeline complet (build puis routes).

const captchaHost = "captcha.example.com"

// nonBrowserAppConfig : l'entrée captcha déclare challenge_enabled false et
// non_browser_paths ["/v1/"]. Les heuristiques de l'anti-bot sont appliquées
// (pas de shadow), comme sur le déploiement audité.
func nonBrowserAppConfig(upstreamURL string, riskEngine bool) config.Config {
	cfg := testAppConfig(upstreamURL)
	cfg.RiskEngine.Enabled = riskEngine
	cfg.RiskEngine.ShadowMode = false
	disabled := false
	cfg.Domains = []config.DomainConfig{{
		Host:             captchaHost,
		Upstream:         upstreamURL,
		ChallengeEnabled: &disabled,
		NonBrowserPaths:  []string{"/v1/"},
	}}
	return cfg
}

// serverCall est un appel de backend intégrateur relayé par Cloudflare :
// User-Agent de librairie HTTP, ni Accept-Language ni Accept-Encoding.
func serverCall(method, path, clientIP string) *http.Request {
	request := httptest.NewRequest(method, "http://"+captchaHost+path, nil)
	request.RemoteAddr = cloudflareEdge
	request.Header.Set("CF-Connecting-IP", clientIP)
	request.Header.Set("User-Agent", "node")
	return request
}

// « Appels serveur répétés sur un préfixe exempté » : 100 POST /v1/siteverify
// passent, alors que le même flux sur / est bloqué.
func TestAppNonBrowserPathsLetServerCallsThrough(t *testing.T) {
	for _, mode := range []struct {
		name       string
		riskEngine bool
	}{
		{name: "trust score gate", riskEngine: false},
		{name: "risk engine enforced", riskEngine: true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			upstream := newUpstreamRecorder(t)
			cfg := nonBrowserAppConfig(upstream.server.URL, mode.riskEngine)
			// Le volume n'est pas l'objet de ce scénario (voir le rate limiting).
			cfg.RateLimit.RequestsPerSecond = 1000
			cfg.RateLimit.Burst = 1000
			handler := newTestApp(t, cfg)

			for i := range 100 {
				if response := serve(handler, serverCall(http.MethodPost, "/v1/siteverify", "203.0.113.7")); response.Code != http.StatusNoContent {
					t.Fatalf("POST /v1/siteverify #%d: status = %d, reason = %q; want 204", i+1, response.Code, response.Header().Get("X-WAF-Reason"))
				}
			}
			metrics := serve(handler, httptest.NewRequest(http.MethodGet, "http://example.test/waf/metrics", nil)).Body.String()
			if want := `waf_antibot_non_browser_exempt_total{domain="captcha.example.com"} 100`; !strings.Contains(metrics, want) {
				t.Fatalf("metrics missing %q", want)
			}

			blocked := false
			for range 100 {
				if response := serve(handler, serverCall(http.MethodPost, "/", "203.0.113.8")); response.Code == http.StatusForbidden {
					blocked = true
					break
				}
			}
			if !blocked {
				t.Fatal("POST / with the same client: never 403, want the anti-bot penalty outside non_browser_paths")
			}
		})
	}
}

// Les défenses de volume, la blacklist et le honeypot restent appliqués sous
// un chemin exempté.
func TestAppNonBrowserPathsKeepOtherDefenses(t *testing.T) {
	t.Run("rate limiting", func(t *testing.T) {
		upstream := newUpstreamRecorder(t)
		cfg := nonBrowserAppConfig(upstream.server.URL, false)
		cfg.RateLimit.Burst = 100
		handler := newTestApp(t, cfg)

		var limited *httptest.ResponseRecorder
		for range 150 {
			if response := serve(handler, serverCall(http.MethodPost, "/v1/siteverify", "203.0.113.10")); response.Code == http.StatusTooManyRequests {
				limited = response
				break
			}
		}
		if limited == nil {
			t.Fatal("150 POST /v1/siteverify with burst 100: no 429")
		}
		if limited.Header().Get("Retry-After") == "" {
			t.Fatal("429 without Retry-After")
		}
	})

	t.Run("blacklist", func(t *testing.T) {
		upstream := newUpstreamRecorder(t)
		cfg := nonBrowserAppConfig(upstream.server.URL, false)
		cfg.Blacklist = []string{"198.51.100.1"}
		handler := newTestApp(t, cfg)

		if response := serve(handler, serverCall(http.MethodPost, "/v1/siteverify", "198.51.100.1")); response.Code != http.StatusForbidden {
			t.Fatalf("blacklisted IP: status = %d, want 403", response.Code)
		}
	})

	t.Run("honeypot ban", func(t *testing.T) {
		upstream := newUpstreamRecorder(t)
		cfg := nonBrowserAppConfig(upstream.server.URL, true)
		cfg.HoneypotPaths = append(cfg.HoneypotPaths, "/v1/.env")
		handler := newTestApp(t, cfg)

		trap := serve(handler, serverCall(http.MethodGet, "/v1/.env", "203.0.113.9"))
		if trap.Code != http.StatusForbidden || trap.Header().Get("X-WAF-Action") != "HONEYPOT" {
			t.Fatalf("GET /v1/.env: status = %d, action = %q; want 403 HONEYPOT", trap.Code, trap.Header().Get("X-WAF-Action"))
		}
		response := serve(handler, serverCall(http.MethodPost, "/v1/siteverify", "203.0.113.9"))
		if response.Code != http.StatusForbidden || response.Header().Get("X-WAF-Reason") != "honeypot_ban" {
			t.Fatalf("POST /v1/siteverify after the trap: status = %d, reason = %q; want 403 honeypot_ban", response.Code, response.Header().Get("X-WAF-Reason"))
		}
	})
}
