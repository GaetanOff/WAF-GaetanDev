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
