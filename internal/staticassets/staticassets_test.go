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

// FR-24 : seuls GET et HEAD lisent un asset. Une écriture vers un chemin
// d'asset traverse le pipeline complet.
func TestOnlyReadMethodsAreBypassed(t *testing.T) {
	tests := []struct {
		method   string
		wantPass bool
	}{
		{method: http.MethodGet, wantPass: true},
		{method: http.MethodHead, wantPass: true},
		{method: http.MethodPost, wantPass: false},
		{method: http.MethodPut, wantPass: false},
		{method: http.MethodPatch, wantPass: false},
		{method: http.MethodDelete, wantPass: false},
		{method: http.MethodOptions, wantPass: false},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			counted := 0
			var action string
			testBypass().WithCounter(func(string) { counted++ }).Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				action = r.Header.Get("X-WAF-Action")
			})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tt.method, "http://x/login.css", nil))

			if (action == "PASS") != tt.wantPass {
				t.Fatalf("%s /login.css: X-WAF-Action = %q, want PASS=%v", tt.method, action, tt.wantPass)
			}
			if (counted == 1) != tt.wantPass {
				t.Fatalf("%s /login.css: counted %d asset requests, want PASS=%v", tt.method, counted, tt.wantPass)
			}
		})
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

// FR-24 : bypass par chemin exact et par préfixe de répertoire, en plus de
// l'extension ; préfixes et chemins exacts sont sensibles à la casse.
func TestExactPathsAndPrefixesAreAssets(t *testing.T) {
	bypass := New(config.StaticAssets{
		Enabled:      true,
		Extensions:   []string{".css"},
		PathPrefixes: []string{"/static/", "/assets/"},
		ExactPaths:   []string{"/robots.txt", "/sitemap.xml"},
	})
	tests := []struct {
		path      string
		wantAsset bool
	}{
		{path: "/robots.txt", wantAsset: true},
		{path: "/sitemap.xml", wantAsset: true},
		{path: "/assets/vendor/react.min.js", wantAsset: true},
		{path: "/static/build-manifest", wantAsset: true},
		{path: "/robots.txt/admin", wantAsset: false},
		{path: "/ROBOTS.TXT", wantAsset: false},
		{path: "/STATIC/app", wantAsset: false},
		{path: "/staticfoo", wantAsset: false},
		{path: "/api/data.json", wantAsset: false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			var counted []string
			var action string
			bypass.WithCounter(func(host string) { counted = append(counted, host) }).Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				action = r.Header.Get("X-WAF-Action")
			})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test"+tt.path, nil))

			if (action == "PASS") != tt.wantAsset {
				t.Fatalf("X-WAF-Action = %q, want asset=%v", action, tt.wantAsset)
			}
			if tt.wantAsset && (len(counted) != 1 || counted[0] != "example.test") {
				t.Fatalf("counted = %v, want one asset request for example.test", counted)
			}
			if !tt.wantAsset && len(counted) != 0 {
				t.Fatalf("counted = %v, want none for a non-asset", counted)
			}
		})
	}
}
