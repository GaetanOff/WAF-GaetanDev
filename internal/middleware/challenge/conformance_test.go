package challenge

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/trust"
)

// Tests de conformance dérivés de specs/features/js-challenge.feature.
// Chaque test référence le scénario Gherkin qu'il valide.

// Scenario: Page challenge — branding et chronomètre présents.
// Charge le vrai template web/challenge.html via NewMiddleware (chemin fichier).
func TestConformanceRealTemplateBrandingAndTimer(t *testing.T) {
	middleware := newRealTemplateMiddleware(t)
	request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
	request.RemoteAddr = "3.3.3.3:1234"
	request.Header.Set("Accept", "text/html")
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not be called for an unchallenged visitor")
	})).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	body := response.Body.String()
	wantSubstrings := []string{
		"Protected by GaetanDev.fr",     // branding
		"https://firewall.gaetandev.fr", // lien de marque
		"moveBackground",                // animation CSS
		`id="elapsed"`,                  // chronomètre visible
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(body, want) {
			t.Fatalf("challenge page missing %q", want)
		}
	}
}

// Scenario: Adaptation automatique du thème à la préférence système du visiteur.
// La page bascule en thème sombre via @media (prefers-color-scheme: dark),
// sans JavaScript ni bouton de sélection de thème.
func TestConformanceRealTemplateAutoDarkMode(t *testing.T) {
	middleware := newRealTemplateMiddleware(t)
	request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
	request.RemoteAddr = "3.3.3.3:1234"
	request.Header.Set("Accept", "text/html")
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(response, request)

	body := response.Body.String()
	if !strings.Contains(body, "prefers-color-scheme: dark") {
		t.Fatal("challenge page missing @media (prefers-color-scheme: dark) rule")
	}
}

// Scenario: Page challenge — la page ne charge aucune ressource externe (pas de CDN).
func TestConformanceRealTemplateHasNoExternalResources(t *testing.T) {
	middleware := newRealTemplateMiddleware(t)
	request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
	request.RemoteAddr = "3.3.3.3:1234"
	request.Header.Set("Accept", "text/html")
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(response, request)

	body := response.Body.String()
	for _, forbidden := range []string{"src=\"http", "src='http", "<link", "cdn."} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("challenge page loads an external resource: found %q", forbidden)
		}
	}
}

// NewMiddleware — chemins d'erreur du constructeur (fichier et durées).
func TestConformanceNewMiddlewareErrors(t *testing.T) {
	store := memory.New(10)
	defer store.Close()
	manager, err := trust.NewScoreManager(store, baseChallengeConfig())
	if err != nil {
		t.Fatalf("NewScoreManager() error = %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*config.Config)
		path    string
		wantErr string
	}{
		{
			name:    "missing template file",
			mutate:  func(*config.Config) {},
			path:    filepath.Join(t.TempDir(), "does-not-exist.html"),
			wantErr: "read challenge template",
		},
		{
			name:    "invalid token_ttl",
			mutate:  func(c *config.Config) { c.Challenge.TokenTTL = "not-a-duration" },
			path:    writeTempTemplate(t),
			wantErr: "challenge.token_ttl",
		},
		{
			name:    "invalid cookie_ttl",
			mutate:  func(c *config.Config) { c.Challenge.CookieTTL = "not-a-duration" },
			path:    writeTempTemplate(t),
			wantErr: "challenge.cookie_ttl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseChallengeConfig()
			tt.mutate(&cfg)
			_, err := NewMiddleware(cfg, manager, tt.path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("NewMiddleware() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

// NewMiddleware — chargement réussi depuis un fichier template valide.
func TestConformanceNewMiddlewareLoadsTemplateFromFile(t *testing.T) {
	store := memory.New(10)
	defer store.Close()
	manager, err := trust.NewScoreManager(store, baseChallengeConfig())
	if err != nil {
		t.Fatalf("NewScoreManager() error = %v", err)
	}

	middleware, err := NewMiddleware(baseChallengeConfig(), manager, writeTempTemplate(t))
	if err != nil {
		t.Fatalf("NewMiddleware() error = %v", err)
	}
	if middleware.template == nil {
		t.Fatal("template not loaded")
	}
}

// Scenario: Cookie falsifié (HMAC invalide) — le WAF sert la page de challenge.
func TestConformanceForgedCookieServesChallengePage(t *testing.T) {
	middleware, store := newTestChallengeMiddleware(t)
	defer store.Close()
	cookie, err := middleware.cookieIssuer.Issue("3.3.3.3", "example.test", strings.Repeat("a", 64), 75, time.Hour)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	cookie.Value += "tampered" // casse la signature HMAC

	request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
	request.RemoteAddr = "3.3.3.3:1234"
	request.Header.Set("Accept", "text/html")
	request.AddCookie(&cookie)
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("forged cookie must not reach the upstream")
	})).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (challenge page)", response.Code)
	}
	if !strings.Contains(response.Body.String(), "Protected by GaetanDev.fr") {
		t.Fatalf("forged cookie did not fall through to the challenge page")
	}
}

// Scenario: Cookie expiré — le WAF sert la page de challenge.
func TestConformanceExpiredCookieServesChallengePage(t *testing.T) {
	middleware, store := newTestChallengeMiddleware(t)
	defer store.Close()
	cookie, err := middleware.cookieIssuer.Issue("3.3.3.3", "example.test", strings.Repeat("a", 64), 75, -time.Hour)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
	request.RemoteAddr = "3.3.3.3:1234"
	request.Header.Set("Accept", "text/html")
	request.AddCookie(&cookie)
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("expired cookie must not reach the upstream")
	})).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (challenge page)", response.Code)
	}
}

// Un visiteur déjà marqué PASS en amont est transmis sans challenge.
func TestConformancePassActionSkipsChallenge(t *testing.T) {
	middleware, store := newTestChallengeMiddleware(t)
	defer store.Close()
	request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
	request.RemoteAddr = "3.3.3.3:1234"
	request.Header.Set("Accept", "text/html")
	request.Header.Set("X-WAF-Action", "PASS")
	response := httptest.NewRecorder()

	nextCalled := false
	middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)

	if !nextCalled {
		t.Fatal("PASS action should forward to the upstream")
	}
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}

// POST /waf/verify — méthode GET rejetée (405).
func TestConformanceVerifyRejectsNonPost(t *testing.T) {
	middleware, store := newTestChallengeMiddleware(t)
	defer store.Close()
	request := httptest.NewRequest(http.MethodGet, "http://example.test/waf/verify", nil)
	request.RemoteAddr = "3.3.3.3:1234"
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", response.Code)
	}
}

// POST /waf/verify — corps malformé ou champs inconnus rejetés.
func TestConformanceVerifyRejectsMalformedBody(t *testing.T) {
	middleware, store := newTestChallengeMiddleware(t)
	defer store.Close()

	tests := []struct {
		name string
		body string
	}{
		{name: "invalid json", body: "{not-json"},
		{name: "unknown field", body: `{"token":"t","nonce":"1","elapsed_ms":1200,"surprise":true}`},
		// encoding/json v1 acceptait ces deux corps : le membre dupliqué selon la
		// règle « le dernier gagne » (différentiel de parseur avec l'origine), et
		// l'UTF-8 invalide en le remplaçant par U+FFFD (valeur inspectée altérée).
		{name: "duplicate member name", body: `{"token":"a","token":"t","nonce":"1","elapsed_ms":1200}`},
		{name: "invalid utf-8", body: `{"token":"t` + string([]byte{0xed, 0xa0, 0x80}) + `","nonce":"1","elapsed_ms":1200}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := verifyRequest(t, "3.3.3.3:1234", tt.body)
			response := httptest.NewRecorder()

			middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", response.Code)
			}
			if !strings.Contains(response.Body.String(), "invalid_submission") {
				t.Fatalf("response missing invalid_submission: %s", response.Body.String())
			}
		})
	}
}

// POST /waf/verify — token forgé rejeté avec invalid_token.
func TestConformanceVerifyRejectsForgedToken(t *testing.T) {
	middleware, store := newTestChallengeMiddleware(t)
	defer store.Close()
	request := verifyRequest(t, "3.3.3.3:1234", submissionJSON("forged.token.value", "1", 1200))
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
	if !strings.Contains(response.Body.String(), "invalid_token") {
		t.Fatalf("response missing invalid_token: %s", response.Body.String())
	}
}

// validateSubmission — champs obligatoires manquants.
func TestConformanceValidateSubmission(t *testing.T) {
	tests := []struct {
		name       string
		submission Submission
		wantErr    bool
	}{
		{name: "valid", submission: Submission{Token: "t", Nonce: "1", ElapsedMS: 1200}, wantErr: false},
		{name: "missing token", submission: Submission{Nonce: "1", ElapsedMS: 1200}, wantErr: true},
		{name: "missing nonce", submission: Submission{Token: "t", ElapsedMS: 1200}, wantErr: true},
		{name: "negative elapsed", submission: Submission{Token: "t", Nonce: "1", ElapsedMS: -1}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSubmission(tt.submission)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateSubmission() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func baseChallengeConfig() config.Config {
	cfg := config.Default()
	cfg.Version = "1.0"
	cfg.Server.Listen = ":0"
	cfg.Upstream.Address = "http://example.test"
	cfg.Challenge.SecretKey = testKey
	cfg.Challenge.PowDifficulty = 8
	cfg.Challenge.MinElapsedMS = 500
	cfg.Challenge.MaxElapsedMS = 10000
	cfg.Admin.Enabled = false
	return cfg
}

func newRealTemplateMiddleware(t *testing.T) Middleware {
	t.Helper()
	store := memory.New(100)
	t.Cleanup(store.Close)
	manager, err := trust.NewScoreManager(store, baseChallengeConfig())
	if err != nil {
		t.Fatalf("NewScoreManager() error = %v", err)
	}
	templatePath := filepath.Join("..", "..", "..", "web", "challenge.html")
	middleware, err := NewMiddleware(baseChallengeConfig(), manager, templatePath)
	if err != nil {
		t.Fatalf("NewMiddleware() error = %v", err)
	}
	return middleware
}

func writeTempTemplate(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "challenge.html")
	content := `Protected by GaetanDev.fr {{.Token}} {{.Difficulty}} {{.RedirectURL}}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp template: %v", err)
	}
	return path
}
