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

// Une origine down renvoie souvent un 502 en text/html (page générique
// nginx/OpenResty). Sur une navigation navigateur, le WAF DOIT la brander.
func TestErrorPageBrandsHTMLGatewayError(t *testing.T) {
	m := New(config.Maintenance{Enabled: false, ErrorPages: true})
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html><head><title>502 Bad Gateway</title></head><body><center>openresty/1.27.1.1</center></body></html>"))
	}))
	resp := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	request.Header.Set("Accept", "text/html")
	handler.ServeHTTP(resp, request)

	if resp.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.Code)
	}
	body := resp.Body.String()
	if !strings.Contains(body, "Protected by") {
		t.Fatalf("5xx HTML gateway error must be branded: %q", body)
	}
	if strings.Contains(body, "openresty") {
		t.Fatalf("original upstream gateway page leaked: %q", body)
	}
}

// Un 4xx déjà en HTML (page d'erreur légitime d'une appli) reste préservé même
// sur une navigation navigateur : on ne brande que les 4xx non-HTML.
func TestErrorPagePreserves4xxHTMLForBrowser(t *testing.T) {
	m := New(config.Maintenance{Enabled: false, ErrorPages: true})
	handler := m.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html>page introuvable (custom app)</html>"))
	}))
	resp := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	request.Header.Set("Accept", "text/html")
	handler.ServeHTTP(resp, request)

	if resp.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.Code)
	}
	if !strings.Contains(resp.Body.String(), "custom app") {
		t.Fatalf("legit 4xx HTML app page must be preserved: %q", resp.Body.String())
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
