package challenge

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/trust"
)

func TestMiddlewareServesChallengePageWithoutCookie(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	request := httptest.NewRequest(http.MethodGet, "http://example.test/article/123?ref=x", nil)
	request.RemoteAddr = "3.3.3.3:1234"
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not be called")
	})).ServeHTTP(response, request)

	body := response.Body.String()
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if !strings.Contains(body, "Protected by GaetanDev.fr") {
		t.Fatalf("challenge page missing branding")
	}
	if !strings.Contains(body, "/article/123?ref=x") {
		t.Fatalf("challenge page missing redirect URL")
	}
}

func TestMiddlewareVerifySuccessIssuesCookieAndRedirect(t *testing.T) {
	middleware, store := newTestChallengeMiddleware(t)
	defer store.Close()
	middleware.scores.Set("3.3.3.3", "example.test", 35)
	token, err := middleware.tokenIssuer.GenerateForRedirect("3.3.3.3", "example.test", "/page")
	if err != nil {
		t.Fatalf("GenerateForRedirect() error = %v", err)
	}
	nonce := solvePow(t, token, middleware.difficulty)
	request := verifyRequest(t, "3.3.3.3:1234", submissionJSON(token, nonce, 1200))
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not be called")
	})).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", response.Code, response.Body.String())
	}
	result := response.Result()
	defer func() { _ = result.Body.Close() }()
	if len(result.Cookies()) != 1 {
		t.Fatalf("expected one Set-Cookie, got %d", len(result.Cookies()))
	}
	var payload verifyResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.RedirectURL != "/page" {
		t.Fatalf("redirect_url = %q, want /page", payload.RedirectURL)
	}
	visitor, ok := store.GetVisitor(trust.HashIP("3.3.3.3"))
	if !ok || visitor.Score != 60 {
		t.Fatalf("score = %v ok=%v, want 60", visitor, ok)
	}
}

func TestMiddlewarePassesWithValidCookie(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	cookie, err := middleware.cookieIssuer.Issue("3.3.3.3", "example.test", strings.Repeat("a", 64), 75, time.Hour)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
	request.RemoteAddr = "3.3.3.3:1234"
	request.AddCookie(&cookie)
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}

func TestMiddlewareVerifyInvalidPowDecrementsScore(t *testing.T) {
	middleware, store := newTestChallengeMiddleware(t)
	defer store.Close()
	token, err := middleware.tokenIssuer.GenerateForRedirect("3.3.3.3", "example.test", "/page")
	if err != nil {
		t.Fatalf("GenerateForRedirect() error = %v", err)
	}
	request := verifyRequest(t, "3.3.3.3:1234", submissionJSON(token, "0", 1200))
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
	if !strings.Contains(response.Body.String(), "invalid_pow") {
		t.Fatalf("response missing invalid_pow: %s", response.Body.String())
	}
	visitor, ok := store.GetVisitor(trust.HashIP("3.3.3.3"))
	if !ok || visitor.Score != 30 {
		t.Fatalf("score = %v ok=%v, want 30", visitor, ok)
	}
}

func TestMiddlewareVerifyHeadlessWebGLDecrementsScore(t *testing.T) {
	middleware, store := newTestChallengeMiddleware(t)
	defer store.Close()
	token, err := middleware.tokenIssuer.GenerateForRedirect("3.3.3.3", "example.test", "/page")
	if err != nil {
		t.Fatalf("GenerateForRedirect() error = %v", err)
	}
	nonce := solvePow(t, token, middleware.difficulty)
	request := verifyRequest(t, "3.3.3.3:1234", submissionJSONWithRenderer(token, nonce, 1200, "Google SwiftShader"))
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
	if !strings.Contains(response.Body.String(), "headless_webgl_renderer") {
		t.Fatalf("response missing headless_webgl_renderer: %s", response.Body.String())
	}
	visitor, ok := store.GetVisitor(trust.HashIP("3.3.3.3"))
	if !ok || visitor.Score != 20 {
		t.Fatalf("score = %v ok=%v, want 20", visitor, ok)
	}
}

func TestMiddlewareVerifyRejectsTimingErrors(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	token, err := middleware.tokenIssuer.GenerateForRedirect("3.3.3.3", "example.test", "/page")
	if err != nil {
		t.Fatalf("GenerateForRedirect() error = %v", err)
	}
	nonce := solvePow(t, token, middleware.difficulty)

	tests := []struct {
		name      string
		elapsedMS int
		want      string
	}{
		{name: "too fast", elapsedMS: 50, want: "challenge_too_fast"},
		{name: "timeout", elapsedMS: 15000, want: "challenge_timeout"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := verifyRequest(t, "3.3.3.3:1234", submissionJSON(token, nonce, tt.elapsedMS))
			response := httptest.NewRecorder()

			middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", response.Code)
			}
			if !strings.Contains(response.Body.String(), tt.want) {
				t.Fatalf("response missing %s: %s", tt.want, response.Body.String())
			}
		})
	}
}

func TestMiddlewareVerifyRejectsExpiredToken(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	middleware.tokenIssuer.Now = func() time.Time { return now }
	token, err := middleware.tokenIssuer.GenerateForRedirect("3.3.3.3", "example.test", "/page")
	if err != nil {
		t.Fatalf("GenerateForRedirect() error = %v", err)
	}
	middleware.tokenIssuer.Now = func() time.Time { return now.Add(31 * time.Second) }
	request := verifyRequest(t, "3.3.3.3:1234", submissionJSON(token, "0", 1200))
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "token_expired") {
		t.Fatalf("response = %d %s, want token_expired", response.Code, response.Body.String())
	}
}

func newTestChallengeMiddleware(t *testing.T) (Middleware, *memory.Store) {
	t.Helper()
	store := memory.New(100)
	cfg := config.Default()
	cfg.Version = "1.0"
	cfg.Server.Listen = ":0"
	cfg.Upstream.Address = "http://example.test"
	cfg.Challenge.SecretKey = testKey
	cfg.Challenge.PowDifficulty = 8
	cfg.Challenge.MinElapsedMS = 500
	cfg.Challenge.MaxElapsedMS = 10000
	cfg.Admin.Enabled = false
	manager, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("NewScoreManager() error = %v", err)
	}
	pageTemplate := template.Must(template.New("challenge").Parse(`Protected by GaetanDev.fr {{.Token}} {{.Difficulty}} {{.RedirectURL}}`))
	middleware, err := NewMiddlewareFromTemplate(cfg, manager, pageTemplate)
	if err != nil {
		t.Fatalf("NewMiddlewareFromTemplate() error = %v", err)
	}
	return middleware, store
}

func verifyRequest(t *testing.T, remoteAddr string, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "http://example.test/waf/verify", strings.NewReader(body))
	request.RemoteAddr = remoteAddr
	request.Header.Set("Content-Type", "application/json")
	return request
}

func submissionJSON(token string, nonce string, elapsedMS int) string {
	return submissionJSONWithRenderer(token, nonce, elapsedMS, "ANGLE")
}

func submissionJSONWithRenderer(token string, nonce string, elapsedMS int, renderer string) string {
	return fmt.Sprintf(`{
		"token": %q,
		"nonce": %q,
		"elapsed_ms": %d,
		"fingerprint": {
			"ua": "Mozilla/5.0",
			"tz": 0,
			"lang": "en-US",
			"screen": "1920x1080x24",
			"cpu": 4,
			"touch": 0,
			"canvas_hash": "%s",
			"webgl_renderer": %q,
			"plugins": 3
		}
	}`, token, nonce, elapsedMS, strings.Repeat("a", 64), renderer)
}

func solvePow(t *testing.T, token string, difficultyBits int) string {
	t.Helper()
	for nonce := uint64(0); nonce < 10_000_000; nonce++ {
		nonceText := strconv.FormatUint(nonce, 10)
		sum := sha256.Sum256([]byte(token + nonceText))
		if hasLeadingZeroBits(sum[:], difficultyBits) {
			return nonceText
		}
	}
	t.Fatal("could not solve PoW")
	return ""
}
