package staticassets

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gaetandev/waf/internal/config"
)

func testBypass() Bypass {
	return New(config.StaticAssets{Enabled: true, Extensions: []string{".css", ".js", ".png"}})
}

func TestAssetMarkedPass(t *testing.T) {
	var action string
	testBypass().Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action = r.Header.Get("X-WAF-Action")
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://x/assets/app.css", nil))

	if action != "PASS" {
		t.Fatalf("X-WAF-Action = %q, want PASS for .css", action)
	}
}

func TestNonAssetNotMarked(t *testing.T) {
	var action string
	testBypass().Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action = r.Header.Get("X-WAF-Action")
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://x/account/login", nil))

	if action == "PASS" {
		t.Fatal("dynamic path must not be marked PASS")
	}
}

func TestDisabledBypassDoesNothing(t *testing.T) {
	bypass := New(config.StaticAssets{Enabled: false, Extensions: []string{".css"}})
	var action string
	bypass.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action = r.Header.Get("X-WAF-Action")
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://x/app.css", nil))

	if action == "PASS" {
		t.Fatal("disabled bypass must not mark PASS")
	}
}
