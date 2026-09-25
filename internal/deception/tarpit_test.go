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
	// Journalisée et comptée TARPIT par le logger et les métriques.
	if got := response.Header().Get("X-WAF-Action"); got != "TARPIT" {
		t.Fatalf("X-WAF-Action = %q, want TARPIT", got)
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
	if action, reason := response.Header().Get("X-WAF-Action"), response.Header().Get("X-WAF-Reason"); action != "TARPIT" || reason != ReasonSaturated {
		t.Fatalf("X-WAF-Action/Reason = %q/%q, want TARPIT/%s", action, reason, ReasonSaturated)
	}
}

// FR-15 : chaque chunk est poussé au client, même à travers les wrappers de
// ResponseWriter des middlewares en amont, qui n'implémentent que Unwrap.
func TestTarpitFlushesEachChunkThroughWrappedWriters(t *testing.T) {
	const chunks = 4
	tarpit := NewTarpit(1, chunks, time.Millisecond)
	handler := tarpit.Dispatch(http.NotFoundHandler())
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set(tarpitActionHeader, "TARPIT")
	flusher := &countingFlusher{ResponseRecorder: httptest.NewRecorder()}

	handler.ServeHTTP(unwrapOnlyWriter{flusher}, request)

	if flusher.flushes != chunks {
		t.Fatalf("flushes = %d, want %d (one per chunk)", flusher.flushes, chunks)
	}
}

// unwrapOnlyWriter reproduit les statusRecorder du pipeline : ni Flush ni
// autre interface optionnelle, seulement Unwrap.
type unwrapOnlyWriter struct{ w http.ResponseWriter }

func (u unwrapOnlyWriter) Header() http.Header         { return u.w.Header() }
func (u unwrapOnlyWriter) Write(b []byte) (int, error) { return u.w.Write(b) }
func (u unwrapOnlyWriter) WriteHeader(code int)        { u.w.WriteHeader(code) }
func (u unwrapOnlyWriter) Unwrap() http.ResponseWriter { return u.w }

type countingFlusher struct {
	*httptest.ResponseRecorder
	flushes int
}

func (c *countingFlusher) Flush() {
	c.flushes++
	c.ResponseRecorder.Flush()
}
