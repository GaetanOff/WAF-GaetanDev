package maintenance

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gaetandev/waf/internal/config"
)

func TestMaintenanceModeServes503ForAllButInternal(t *testing.T) {
	m := New(config.Maintenance{Enabled: true, ErrorPages: true})
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "http://x/page", nil))
	if resp.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "Protected by") {
		t.Fatal("maintenance page missing branding")
	}

	// /waf/health exempté.
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "http://x/waf/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200 (bypassed)", health.Code)
	}
}

func TestErrorPageReplacesPlainBodyForBrowserNavigation(t *testing.T) {
	m := New(config.Maintenance{Enabled: false, ErrorPages: true})
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	resp := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	request.Header.Set("Accept", "text/html") // navigation navigateur
	handler.ServeHTTP(resp, request)

	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.Code)
	}
	body := resp.Body.String()
	if !strings.Contains(body, "<html") || !strings.Contains(body, "Protected by") {
		t.Fatalf("error body not replaced by branded page: %q", body)
	}
	if strings.Contains(body, "forbidden\n") {
		t.Fatal("original plain body leaked")
	}
}

// Un appel API (Accept != text/html) doit conserver le corps d'erreur d'origine
// (souvent JSON) : sinon les clients fetch/axios ne peuvent plus le parser.
func TestErrorPagePreservesApiErrorBody(t *testing.T) {
	m := New(config.Maintenance{Enabled: false, ErrorPages: true})
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":401,"message":"Wrong username or password."}`))
	}))
	for _, accept := range []string{"application/json", "application/json, text/plain, */*", "*/*", ""} {
		resp := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "http://x/rest/login", nil)
		if accept != "" {
			request.Header.Set("Accept", accept)
		}
		handler.ServeHTTP(resp, request)

		if resp.Code != http.StatusUnauthorized {
			t.Fatalf("Accept=%q: status = %d, want 401", accept, resp.Code)
		}
		body := resp.Body.String()
		if !strings.Contains(body, `"message":"Wrong username or password."`) {
			t.Fatalf("Accept=%q: API JSON error body was clobbered: %q", accept, body)
		}
		if strings.Contains(body, "Protected by") {
			t.Fatalf("Accept=%q: API error must not get branded HTML page", accept)
		}
	}
}

func TestErrorPagePreservesSuccessAndHTML(t *testing.T) {
	m := New(config.Maintenance{ErrorPages: true})

	ok := httptest.NewRecorder()
	m.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello"))
	})).ServeHTTP(ok, httptest.NewRequest(http.MethodGet, "http://x/", nil))
	if ok.Body.String() != "hello" {
		t.Fatalf("200 body altered: %q", ok.Body.String())
	}

	// Une erreur déjà en HTML (ex: page de challenge) n'est pas remplacée.
	htmlErr := httptest.NewRecorder()
	m.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html>custom</html>"))
	})).ServeHTTP(htmlErr, httptest.NewRequest(http.MethodGet, "http://x/", nil))
	if !strings.Contains(htmlErr.Body.String(), "custom") {
		t.Fatalf("existing HTML error must be preserved: %q", htmlErr.Body.String())
	}
}

func TestDisabledIsPassthrough(t *testing.T) {
	m := New(config.Maintenance{Enabled: false, ErrorPages: false})
	resp := httptest.NewRecorder()
	m.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})).ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "http://x/", nil))
	if !strings.Contains(resp.Body.String(), "forbidden") {
		t.Fatal("disabled middleware must pass body through unchanged")
	}
}
