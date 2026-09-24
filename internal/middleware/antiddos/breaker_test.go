package antiddos

import (
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/storage"
	"github.com/gaetandev/waf/internal/storage/memory"
)

func TestCircuitBreakerOpensAfterFiveViolationsAndExpires(t *testing.T) {
	store := memory.New(100)
	defer store.Close()
	now := time.Now()
	breaker := NewCircuitBreaker(store, DefaultViolationThreshold, DefaultOpenDuration)
	breaker.now = func() time.Time { return now }

	for range 4 {
		breaker.RecordViolation("1.2.3.4")
		if breaker.IsOpen("1.2.3.4") {
			t.Fatal("circuit should stay closed before the fifth violation")
		}
	}

	visitor := breaker.RecordViolation("1.2.3.4")
	if !visitor.CircuitOpen {
		t.Fatal("circuit should open on fifth violation")
	}
	if visitor.CircuitOpenUntil == nil {
		t.Fatal("circuit_open_until should be set")
	}
	if got := visitor.CircuitOpenUntil.Sub(now); got != DefaultOpenDuration {
		t.Fatalf("open duration = %s, want %s", got, DefaultOpenDuration)
	}
	if !breaker.IsOpen("1.2.3.4") {
		t.Fatal("circuit should be open immediately after fifth violation")
	}

	now = now.Add(DefaultOpenDuration + time.Second)
	if breaker.IsOpen("1.2.3.4") {
		t.Fatal("circuit should close after expiration")
	}
}

// Régression : une requête admise remettait la série à zéro — 4 × 429 puis 1
// requête valide, en boucle, n'ouvraient jamais le circuit.
func TestCircuitBreakerOpensOnPulsedViolations(t *testing.T) {
	store := memory.New(100)
	defer store.Close()
	now := time.Now()
	breaker := NewCircuitBreaker(store, DefaultViolationThreshold, DefaultOpenDuration)
	breaker.now = func() time.Time { return now }

	var visitor storage.VisitorState
	for range DefaultViolationThreshold {
		visitor = breaker.RecordViolation("1.2.3.4")
		now = now.Add(2 * time.Second) // une requête admise s'intercale ici
	}
	if !visitor.CircuitOpen {
		t.Fatalf("violation_count = %d: pulsed violations must still open the circuit", visitor.ViolationCount)
	}
}

func TestCircuitBreakerSeriesExpiresAfterWindow(t *testing.T) {
	store := memory.New(100)
	defer store.Close()
	now := time.Now()
	breaker := NewCircuitBreaker(store, DefaultViolationThreshold, DefaultOpenDuration)
	breaker.now = func() time.Time { return now }

	breaker.RecordViolation("1.2.3.4")
	breaker.RecordViolation("1.2.3.4")
	now = now.Add(DefaultViolationWindow + time.Second)

	visitor := breaker.RecordViolation("1.2.3.4")
	if visitor.ViolationCount != 1 {
		t.Fatalf("violation_count = %d, want 1: an old series must not accumulate", visitor.ViolationCount)
	}
}
