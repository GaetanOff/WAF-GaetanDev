package antiddos

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/storage/memory"
)

func underAttackMiddleware(t *testing.T, shadow bool, now *time.Time) Middleware {
	t.Helper()
	store := memory.New(100)
	t.Cleanup(store.Close)
	breaker := NewCircuitBreaker(store, DefaultViolationThreshold, DefaultOpenDuration)
	det := NewUnderAttackDetector(UnderAttackConfig{
		Enabled:         true,
		PerDomain:       true,
		TriggerPressure: PressureHigh,
		ExitPressure:    PressureElevated,
		Cooldown:        30 * time.Second,
		Shadow:          shadow,
		Threshold:       1,
		Window:          time.Second,
	})
	det.now = func() time.Time { return *now }
	return New(breaker, NewGlobalRateDetector(1, time.Second, PressureConfig{}), DefaultRetryAfterSeconds).
		WithUnderAttackDetector(det)
}

// TestMiddlewareSetsUnderAttackHeaders : sous pression high, le middleware pose
// X-WAF-Under-Attack (journalisé) et X-WAF-Under-Attack-Enforce (forçage challenge).
func TestMiddlewareSetsUnderAttackHeaders(t *testing.T) {
	now := time.Now()
	mw := underAttackMiddleware(t, false, &now)

	var ua, enforce string
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("X-WAF-Under-Attack")
		enforce = r.Header.Get("X-WAF-Under-Attack-Enforce")
		w.WriteHeader(http.StatusNoContent)
	}))

	// 1re requête : elevated -> pas encore sous attaque.
	handler.ServeHTTP(httptest.NewRecorder(), requestFrom("9.9.9.9:1"))
	if ua == "true" {
		t.Fatal("1re requête (elevated) ne doit pas être marquée sous attaque")
	}
	// 2e requête : high -> sous attaque + enforce.
	handler.ServeHTTP(httptest.NewRecorder(), requestFrom("9.9.9.9:2"))
	if ua != "true" || enforce != "true" {
		t.Fatalf("sous attaque: under_attack=%q enforce=%q, want true/true", ua, enforce)
	}
}

// TestMiddlewareShadowSetsStateWithoutEnforcing : en shadow, l'état est journalisé
// mais l'enforcement (challenge forcé) reste désactivé.
func TestMiddlewareShadowSetsStateWithoutEnforcing(t *testing.T) {
	now := time.Now()
	mw := underAttackMiddleware(t, true, &now)

	var ua, enforce string
	handler := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("X-WAF-Under-Attack")
		enforce = r.Header.Get("X-WAF-Under-Attack-Enforce")
		w.WriteHeader(http.StatusNoContent)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), requestFrom("9.9.9.9:1"))
	handler.ServeHTTP(httptest.NewRecorder(), requestFrom("9.9.9.9:2"))
	if ua != "true" {
		t.Fatal("shadow: l'état sous attaque doit être journalisé (under_attack=true)")
	}
	if enforce == "true" {
		t.Fatal("shadow: l'enforcement ne doit pas être activé")
	}
}
