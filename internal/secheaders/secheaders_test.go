package secheaders

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gaetandev/waf/internal/config"
)

func testConfig() config.SecurityHeaders {
	return config.SecurityHeaders{
		Enabled:               true,
		HSTSMaxAge:            31536000,
		HSTSIncludeSubdomains: true,
		FrameOptions:          "DENY",
		ContentTypeNosniff:    true,
		ReferrerPolicy:        "strict-origin-when-cross-origin",
		StripHeaders:          []string{"Server", "X-Powered-By"},
	}
}

func TestInjectsSecurityHeaders(t *testing.T) {
	handler := New(testConfig()).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://x/", nil))

	checks := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
	}
	for name, want := range checks {
		if got := response.Header().Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestUpstreamHeaderHasPriority(t *testing.T) {
	handler := New(testConfig()).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN") // posé par l'upstream
		w.WriteHeader(http.StatusOK)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://x/", nil))

	if got := response.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("X-Frame-Options = %q, want SAMEORIGIN (upstream priority)", got)
	}
}

func TestStripsRevealingHeaders(t *testing.T) {
	handler := New(testConfig()).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.27")
		w.Header().Set("X-Powered-By", "PHP/8.2")
		w.WriteHeader(http.StatusOK)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://x/", nil))

	if response.Header().Get("Server") != "" {
		t.Fatalf("Server header must be stripped, got %q", response.Header().Get("Server"))
	}
	if response.Header().Get("X-Powered-By") != "" {
		t.Fatalf("X-Powered-By must be stripped, got %q", response.Header().Get("X-Powered-By"))
	}
}

func TestCSPOnlyWhenConfigured(t *testing.T) {
	cfg := testConfig()
	handler := New(cfg).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://x/", nil))
	if response.Header().Get("Content-Security-Policy") != "" {
		t.Fatal("CSP must not be set when empty (opt-in)")
	}
}

func serve(cfg config.SecurityHeaders, upstream http.HandlerFunc) http.Header {
	response := httptest.NewRecorder()
	New(cfg).Handler(upstream).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://x/", nil))
	return response.Header()
}

func respondOK(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

// FR-21 : les défauts servis sont ceux de config.Default(), sur une requête
// HTTP (derrière Cloudflare, le WAF reçoit du HTTP et pose tout de même HSTS).
func TestDefaultConfigHeaders(t *testing.T) {
	header := serve(config.Default().SecurityHeaders, respondOK)

	checks := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Permissions-Policy":        "",
		"Content-Security-Policy":   "",
	}
	for name, want := range checks {
		if got := header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestCSPWhenConfigured(t *testing.T) {
	cfg := testConfig()
	cfg.CSP = "default-src 'self'"

	if got := serve(cfg, respondOK).Get("Content-Security-Policy"); got != cfg.CSP {
		t.Fatalf("Content-Security-Policy = %q, want %q", got, cfg.CSP)
	}
}

func TestHSTSDisabledWithZeroMaxAge(t *testing.T) {
	cfg := testConfig()
	cfg.HSTSMaxAge = 0

	if got := serve(cfg, respondOK).Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("Strict-Transport-Security = %q, want none with hsts_max_age 0", got)
	}
}

// FR-22 : strip_headers est la liste à retirer ; l'opérateur l'étend selon sa stack.
func TestStripsConfiguredHeaders(t *testing.T) {
	cfg := testConfig()
	cfg.StripHeaders = []string{"Server", "X-Powered-By", "X-Generator", "Via"}
	header := serve(cfg, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Generator", "WordPress 6.4")
		w.Header().Set("Via", "1.1 nginx")
		w.WriteHeader(http.StatusOK)
	})

	for _, name := range []string{"X-Generator", "Via"} {
		if got := header.Get(name); got != "" {
			t.Errorf("%s = %q, want stripped", name, got)
		}
	}
}
