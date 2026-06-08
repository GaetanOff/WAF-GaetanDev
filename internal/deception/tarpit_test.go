package deception

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDispatchPassesThroughWhenNotTarpit(t *testing.T) {
	tarpit := NewTarpit(10, 5, time.Millisecond)
	called := false
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	tarpit.Dispatch(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), request)

	if !called {
		t.Fatal("non-TARPIT request must reach the proxy")
	}
}

func TestDispatchServesSlowFakeHTML(t *testing.T) {
	tarpit := NewTarpit(10, 4, time.Millisecond)
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.Header.Set("X-WAF-Action", "TARPIT")
	response := httptest.NewRecorder()

	tarpit.Dispatch(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("tarpitted request must not reach the proxy")
	})).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, "<html>") || !strings.Contains(body, "</html>") {
		t.Fatalf("tarpit body is not a full fake HTML page: %q", body)
	}
}

func TestDispatchReturns429WhenSemaphoreFull(t *testing.T) {
	tarpit := NewTarpit(1, 4, time.Millisecond)
	// Sature le sémaphore.
	tarpit.sem <- struct{}{}

	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.Header.Set("X-WAF-Action", "TARPIT")
	response := httptest.NewRecorder()

	tarpit.Dispatch(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(response, request)

	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 when tarpit pool is full", response.Code)
	}
}
