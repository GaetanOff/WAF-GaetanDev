package challenge

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/trust"
)

func boolPtr(v bool) *bool { return &v }

// FR-06 : domains[].challenge_enabled surcharge challenge.enabled par domaine.
func TestDomainGateResolvesOverridePerHost(t *testing.T) {
	tests := []struct {
		name    string
		global  bool
		domains []config.DomainConfig
		host    string
		want    bool
	}{
		{
			name:   "aucun domaine configuré — global appliqué",
			global: true,
			host:   "example.test",
			want:   true,
		},
		{
			name:    "clé absente — le domaine hérite du global",
			global:  true,
			domains: []config.DomainConfig{{Host: "shop.example.com"}},
			host:    "shop.example.com",
			want:    true,
		},
		{
			name:    "clé absente — hérite aussi d'un global désactivé",
			global:  false,
			domains: []config.DomainConfig{{Host: "shop.example.com"}},
			host:    "shop.example.com",
			want:    false,
		},
		{
			name:    "false explicite — challenge désactivé pour ce domaine",
			global:  true,
			domains: []config.DomainConfig{{Host: "api.example.com", ChallengeEnabled: boolPtr(false)}},
			host:    "api.example.com",
			want:    false,
		},
		{
			name:    "true explicite — challenge forcé malgré un global désactivé",
			global:  false,
			domains: []config.DomainConfig{{Host: "boutique.example.com", ChallengeEnabled: boolPtr(true)}},
			host:    "boutique.example.com",
			want:    true,
		},
		{
			name:    "hôte non listé — global appliqué",
			global:  true,
			domains: []config.DomainConfig{{Host: "api.example.com", ChallengeEnabled: boolPtr(false)}},
			host:    "autre.test",
			want:    true,
		},
		{
			name:    "casse et port ignorés",
			global:  true,
			domains: []config.DomainConfig{{Host: "API.Example.com", ChallengeEnabled: boolPtr(false)}},
			host:    "api.EXAMPLE.com:8443",
			want:    false,
		},
		{
			name:    "wildcard — sous-domaine couvert",
			global:  true,
			domains: []config.DomainConfig{{Host: "*.example.com", ChallengeEnabled: boolPtr(false)}},
			host:    "api.example.com",
			want:    false,
		},
		{
			name:    "wildcard — apex couvert",
			global:  true,
			domains: []config.DomainConfig{{Host: "*.example.com", ChallengeEnabled: boolPtr(false)}},
			host:    "example.com",
			want:    false,
		},
		{
			name:   "première correspondance gagne",
			global: true,
			domains: []config.DomainConfig{
				{Host: "api.example.com", ChallengeEnabled: boolPtr(true)},
				{Host: "*.example.com", ChallengeEnabled: boolPtr(false)},
			},
			host: "api.example.com",
			want: true,
		},
		{
			name:    "hôte IPv6 littéral avec port",
			global:  true,
			domains: []config.DomainConfig{{Host: "::1", ChallengeEnabled: boolPtr(false)}},
			host:    "[::1]:8443",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Challenge.Enabled = tt.global
			cfg.Domains = tt.domains
			if got := newDomainGate(cfg).enabledFor(tt.host); got != tt.want {
				t.Fatalf("enabledFor(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

// Enabled décide du montage du middleware dans la chaîne : un domaine qui active
// explicitement le challenge doit le faire monter même si le global est éteint.
func TestEnabledDecidesMounting(t *testing.T) {
	tests := []struct {
		name    string
		global  bool
		domains []config.DomainConfig
		want    bool
	}{
		{name: "global activé", global: true, want: true},
		{name: "global désactivé, aucun domaine", global: false, want: false},
		{
			name:    "global désactivé, domaine à true",
			global:  false,
			domains: []config.DomainConfig{{Host: "boutique.example.com", ChallengeEnabled: boolPtr(true)}},
			want:    true,
		},
		{
			name:    "global désactivé, domaine à false",
			global:  false,
			domains: []config.DomainConfig{{Host: "api.example.com", ChallengeEnabled: boolPtr(false)}},
			want:    false,
		},
		{
			name:    "global activé, tous les domaines à false — reste monté pour les hôtes non listés",
			global:  true,
			domains: []config.DomainConfig{{Host: "api.example.com", ChallengeEnabled: boolPtr(false)}},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Challenge.Enabled = tt.global
			cfg.Domains = tt.domains
			if got := Enabled(cfg); got != tt.want {
				t.Fatalf("Enabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMiddlewareSkipsChallengeOnDisabledDomain(t *testing.T) {
	middleware := newTestChallengeMiddlewareWithDomains(t, true, []config.DomainConfig{
		{Host: "api.example.com", ChallengeEnabled: boolPtr(false)},
	})

	request := httptest.NewRequest(http.MethodGet, "http://api.example.com/page", nil)
	request.RemoteAddr = "3.3.3.3:1234"
	request.Header.Set("Accept", "text/html")
	response := httptest.NewRecorder()

	called := false
	middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(response, request)

	if !called {
		t.Fatal("next handler should be called on a domain with challenge_enabled=false")
	}
	if strings.Contains(response.Body.String(), "Protected by GaetanDev.fr") {
		t.Fatal("challenge page served on a domain with challenge_enabled=false")
	}
}

// Un domaine listé sans la clé challenge_enabled (typiquement pour son seul
// upstream ou son certificat TLS) ne doit pas perdre le challenge : c'est le
// fail-open silencieux qu'évite le *bool.
func TestMiddlewareChallengesDomainWithoutOverride(t *testing.T) {
	middleware := newTestChallengeMiddlewareWithDomains(t, true, []config.DomainConfig{
		{Host: "shop.example.com", Upstream: "http://10.0.0.1:80"},
	})

	request := httptest.NewRequest(http.MethodGet, "http://shop.example.com/page", nil)
	request.RemoteAddr = "3.3.3.3:1234"
	request.Header.Set("Accept", "text/html")
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not be called")
	})).ServeHTTP(response, request)

	if !strings.Contains(response.Body.String(), "Protected by GaetanDev.fr") {
		t.Fatal("domain without the challenge_enabled key must inherit the global setting")
	}
}

// challenge_enabled=false est une décision explicite de l'opérateur : elle prime
// sur l'escalade automatique du mode « sous attaque » (FR-39).
func TestMiddlewareDisabledDomainWinsOverUnderAttack(t *testing.T) {
	middleware := newTestChallengeMiddlewareWithDomains(t, true, []config.DomainConfig{
		{Host: "api.example.com", ChallengeEnabled: boolPtr(false)},
	})

	request := httptest.NewRequest(http.MethodGet, "http://api.example.com/page", nil)
	request.RemoteAddr = "3.3.3.3:1234"
	request.Header.Set("Accept", "text/html")
	request.Header.Set("X-WAF-Under-Attack-Enforce", "true")
	response := httptest.NewRecorder()

	called := false
	middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(response, request)

	if !called {
		t.Fatal("under-attack mode must not override an explicit challenge_enabled=false")
	}
}

// "/waf/" est un préfixe réservé au WAF sur tous les domaines : /waf/verify n'est
// jamais transmis à l'upstream, même là où le challenge est désactivé.
func TestMiddlewareServesVerifyOnDisabledDomain(t *testing.T) {
	middleware := newTestChallengeMiddlewareWithDomains(t, true, []config.DomainConfig{
		{Host: "api.example.com", ChallengeEnabled: boolPtr(false)},
	})

	request := httptest.NewRequest(http.MethodPost, "http://api.example.com/waf/verify", strings.NewReader(`{"token":"","nonce":""}`))
	request.RemoteAddr = "3.3.3.3:1234"
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("/waf/verify must not be forwarded upstream")
	})).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
	if !strings.Contains(response.Body.String(), "invalid_submission") {
		t.Fatalf("body = %q, want invalid_submission", response.Body.String())
	}
}

func newTestChallengeMiddlewareWithDomains(t *testing.T, global bool, domains []config.DomainConfig) Middleware {
	t.Helper()
	cfg := config.Default()
	cfg.Version = "1.0"
	cfg.Server.Listen = ":0"
	cfg.Upstream.Address = "http://example.test"
	cfg.Challenge.SecretKey = testKey
	cfg.Challenge.PowDifficulty = 8
	cfg.Challenge.Enabled = global
	cfg.Domains = domains
	cfg.Admin.Enabled = false
	manager, err := trust.NewScoreManager(memory.New(100), cfg)
	if err != nil {
		t.Fatalf("NewScoreManager() error = %v", err)
	}
	pageTemplate := template.Must(template.New("challenge").Parse(`Protected by GaetanDev.fr {{.Token}}`))
	middleware, err := NewMiddlewareFromTemplate(cfg, manager, pageTemplate)
	if err != nil {
		t.Fatalf("NewMiddlewareFromTemplate() error = %v", err)
	}
	return middleware
}
