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
	middleware := New(NewCircuitBreaker(store, DefaultViolationThreshold, DefaultOpenDuration), nil, DefaultRetryAfterSeconds)
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
	middleware := New(breaker, nil, DefaultRetryAfterSeconds)
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

func TestMiddlewareReturnsDegradedResponseForNewVisitorWhenGlobalRateExceeded(t *testing.T) {
	store := memory.New(100)
	defer store.Close()
	detector := NewGlobalRateDetector(1, time.Second)
	middleware := New(NewCircuitBreaker(store, DefaultViolationThreshold, DefaultOpenDuration), detector, DefaultRetryAfterSeconds)
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, requestFrom("1.2.3.4:1234"))
	if first.Code != http.StatusNoContent {
		t.Fatalf("first status = %d, want 204", first.Code)
	}

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, requestFrom("5.6.7.8:1234"))
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("second status = %d, want 503", second.Code)
	}
	if second.Header().Get("Retry-After") != "5" {
		t.Fatalf("Retry-After = %q, want 5", second.Header().Get("Retry-After"))
	}
	if second.Header().Get("X-WAF-Reason") != "global_rate_exceeded" {
		t.Fatalf("X-WAF-Reason = %q, want global_rate_exceeded", second.Header().Get("X-WAF-Reason"))
	}
}

func TestMiddlewareAllowsKnownVisitorWhenGlobalRateExceeded(t *testing.T) {
	store := memory.New(100)
	defer store.Close()
	breaker := NewCircuitBreaker(store, DefaultViolationThreshold, DefaultOpenDuration)
	breaker.RecordViolation("1.2.3.4")
	breaker.Reset("1.2.3.4")
	detector := NewGlobalRateDetector(1, time.Second)
	middleware := New(breaker, detector, DefaultRetryAfterSeconds)
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), requestFrom("5.6.7.8:1234"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestFrom("1.2.3.4:1234"))
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}

func requestFrom(remoteAddr string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
	request.RemoteAddr = remoteAddr
	return request
}
