package challenge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSameOriginPath(t *testing.T) {
	tests := map[string]string{
		"/page?ref=x":      "/page?ref=x",
		"/":                "/",
		"":                 "/",
		"//evil.com/path":  "/",
		"/\\evil.com":      "/",
		"/\t/evil.com":     "/",
		"https://evil.com": "/",
		"evil.com":         "/",
		"/%2F/evil.com":    "/%2F/evil.com", // encodé : reste un chemin local
	}
	for target, want := range tests {
		if got := sameOriginPath(target); got != want {
			t.Errorf("sameOriginPath(%q) = %q, want %q", target, got, want)
		}
	}
}

// Monté hors du ServeMux (qui nettoie "//"), le middleware ne doit pas
// embarquer une cible protocol-relative dans la page.
func TestServePageNeverEmbedsProtocolRelativeRedirect(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.URL.Path = "//evil.com/path"
	request.RemoteAddr = "3.3.3.3:1234"
	request.Header.Set("Accept", "text/html")
	response := httptest.NewRecorder()

	middleware.Handler(http.NotFoundHandler()).ServeHTTP(response, request)

	if strings.Contains(response.Body.String(), "evil.com") {
		t.Fatalf("challenge page embeds the protocol-relative target: %q", response.Body.String())
	}
}

func TestVerifyNeverReturnsProtocolRelativeRedirect(t *testing.T) {
	middleware, store := newTestChallengeMiddleware(t)
	defer store.Close()
	middleware.scores.Set("3.3.3.3", "example.test", 35)
	token, err := middleware.tokenIssuer.GenerateForRedirect("3.3.3.3", "example.test", "//evil.com/path")
	if err != nil {
		t.Fatalf("GenerateForRedirect() error = %v", err)
	}
	response := httptest.NewRecorder()
	middleware.Handler(http.NotFoundHandler()).ServeHTTP(response, verifyRequest(t, "3.3.3.3:1234", submissionJSON(token, solvePow(t, token, middleware.difficulty), 1200)))

	var payload verifyResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.RedirectURL != "/" {
		t.Fatalf("redirect_url = %q, want /", payload.RedirectURL)
	}
}
