package antiddos

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/storage/memory"
)

func TestMiddlewareBlocksNextRequestAfterFiveViolations(t *testing.T) {
	store := memory.New(100)
	defer store.Close()
	middleware := New(NewCircuitBreaker(store, DefaultViolationThreshold, DefaultOpenDuration))
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-WAF-Action", "RATE_LIMIT")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}))

	for range 5 {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, requestFrom("1.2.3.4:1234"))
		if response.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429", response.Code)
		}
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestFrom("1.2.3.4:1234"))

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if response.Header().Get("X-WAF-Action") != "CIRCUIT_BREAK" {
		t.Fatalf("X-WAF-Action = %q, want CIRCUIT_BREAK", response.Header().Get("X-WAF-Action"))
	}
	if response.Header().Get("X-WAF-Reason") != "circuit_breaker_open" {
		t.Fatalf("X-WAF-Reason = %q, want circuit_breaker_open", response.Header().Get("X-WAF-Reason"))
	}
}

func TestMiddlewareAllowsRequestAfterCircuitExpiration(t *testing.T) {
	store := memory.New(100)
	defer store.Close()
	now := time.Now()
	breaker := NewCircuitBreaker(store, DefaultViolationThreshold, DefaultOpenDuration)
	breaker.now = func() time.Time { return now }
	middleware := New(breaker)
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for range 5 {
		breaker.RecordViolation("1.2.3.4")
	}

	blocked := httptest.NewRecorder()
	handler.ServeHTTP(blocked, requestFrom("1.2.3.4:1234"))
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", blocked.Code)
	}

	now = now.Add(DefaultOpenDuration + time.Second)
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, requestFrom("1.2.3.4:1234"))
	if allowed.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", allowed.Code)
	}
}

func requestFrom(remoteAddr string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
	request.RemoteAddr = remoteAddr
	return request
}
