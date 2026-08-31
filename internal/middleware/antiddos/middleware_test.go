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

func TestCircuitBreakerSetsDeterministicTrigger(t *testing.T) {
	store := memory.New(100)
	defer store.Close()
	breaker := NewCircuitBreaker(store, DefaultViolationThreshold, DefaultOpenDuration)
	middleware := New(breaker, nil, DefaultRetryAfterSeconds)
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for range 5 {
		breaker.RecordViolation("1.2.3.4")
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestFrom("1.2.3.4:1234"))

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if got := response.Header().Get("X-WAF-Deterministic-Trigger"); got != "circuit_breaker" {
		t.Fatalf("X-WAF-Deterministic-Trigger = %q, want circuit_breaker", got)
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

func TestMiddlewareDoesNotReturnDegradedResponseForNewVisitorWhenGlobalRateExceeded(t *testing.T) {
	store := memory.New(100)
	defer store.Close()
	detector := NewGlobalRateDetector(1, time.Second, PressureConfig{})
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
	if second.Code != http.StatusNoContent {
		t.Fatalf("second status = %d, want 204", second.Code)
	}
	if second.Header().Get("Retry-After") != "" {
		t.Fatalf("Retry-After = %q, want empty", second.Header().Get("Retry-After"))
	}
	if second.Header().Get("X-WAF-Reason") != "" {
		t.Fatalf("X-WAF-Reason = %q, want empty", second.Header().Get("X-WAF-Reason"))
	}
}

func TestMiddlewarePublishesGlobalPressureAndRateContribution(t *testing.T) {
	store := memory.New(100)
	defer store.Close()
	detector := NewGlobalRateDetector(1, time.Second, PressureConfig{})
	var observed PressureLevel
	middleware := New(NewCircuitBreaker(store, DefaultViolationThreshold, DefaultOpenDuration), detector, DefaultRetryAfterSeconds).
		WithPressureObserver(func(level PressureLevel) {
			observed = level
		})
	requestCount := 0
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		expectedPressure := string(PressureElevated)
		expectedContribution := "35"
		if requestCount == 2 {
			expectedPressure = string(PressureHigh)
			expectedContribution = "60"
		}
		if got := r.Header.Get("X-WAF-Global-Pressure"); got != expectedPressure {
			t.Fatalf("X-WAF-Global-Pressure = %q, want %s", got, expectedPressure)
		}
		if got := r.Header.Get("X-WAF-Risk-rate"); got != expectedContribution {
			t.Fatalf("X-WAF-Risk-rate = %q, want %s", got, expectedContribution)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), requestFrom("1.2.3.4:1234"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestFrom("5.6.7.8:1234"))

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
	if observed != PressureHigh {
		t.Fatalf("observed pressure = %s, want high", observed)
	}
}

func TestMiddlewareAllowsKnownVisitorWhenGlobalRateExceeded(t *testing.T) {
	store := memory.New(100)
	defer store.Close()
	breaker := NewCircuitBreaker(store, DefaultViolationThreshold, DefaultOpenDuration)
	breaker.RecordViolation("1.2.3.4")
	breaker.Reset("1.2.3.4")
	detector := NewGlobalRateDetector(1, time.Second, PressureConfig{})
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

func TestPressureThrottle429DoesNotFeedBreaker(t *testing.T) {
	store := memory.New(100)
	defer store.Close()
	middleware := New(NewCircuitBreaker(store, DefaultViolationThreshold, DefaultOpenDuration), nil, DefaultRetryAfterSeconds)
	// Simule le middleware ratelimit refusant sous throttle de pression (FR-08).
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-WAF-Action", "RATE_LIMIT")
		w.Header().Set("X-WAF-Reason", reasonPressureThrottle)
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}))

	// Bien au-delà du seuil de violations : le circuit ne doit jamais s'ouvrir.
	for i := range DefaultViolationThreshold * 3 {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, requestFrom("1.2.3.4:1234"))
		if response.Code != http.StatusTooManyRequests {
			t.Fatalf("request %d: status = %d, want 429 (never CIRCUIT_BREAK)", i, response.Code)
		}
	}
}

func TestPressureThrottle429DoesNotResetViolationStreak(t *testing.T) {
	store := memory.New(100)
	defer store.Close()
	breaker := NewCircuitBreaker(store, DefaultViolationThreshold, DefaultOpenDuration)
	middleware := New(breaker, nil, DefaultRetryAfterSeconds)
	handler := middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-WAF-Action", "RATE_LIMIT")
		w.Header().Set("X-WAF-Reason", reasonPressureThrottle)
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}))

	for range DefaultViolationThreshold - 1 {
		breaker.RecordViolation("1.2.3.4")
	}

	// Un 429 de pression est neutre : il ne remet pas la série à zéro.
	handler.ServeHTTP(httptest.NewRecorder(), requestFrom("1.2.3.4:1234"))

	breaker.RecordViolation("1.2.3.4")
	if !breaker.IsOpen("1.2.3.4") {
		t.Fatal("expected circuit to open: pressure 429 must not reset the violation streak")
	}
}

func requestFrom(remoteAddr string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
	request.RemoteAddr = remoteAddr
	return request
}
