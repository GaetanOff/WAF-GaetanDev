package adaptive

import (
	"testing"
	"time"
)

func TestExtraBitsForPressureIsDistinctPerLevel(t *testing.T) {
	tests := []struct {
		level string
		want  int
	}{
		{level: "normal", want: 0},
		{level: "", want: 0},
		{level: "elevated", want: elevatedExtraBits},
		{level: "high", want: highExtraBits},
		{level: "critical", want: criticalExtraBits},
	}
	for _, tt := range tests {
		if got := extraBitsForPressure(tt.level); got != tt.want {
			t.Fatalf("extraBitsForPressure(%q) = %d, want %d", tt.level, got, tt.want)
		}
	}
	// Régression : high et critical ne doivent plus produire la même difficulté.
	if highExtraBits == criticalExtraBits || elevatedExtraBits == highExtraBits {
		t.Fatalf("pressure bit floors must be strictly increasing: elevated=%d high=%d critical=%d",
			elevatedExtraBits, highExtraBits, criticalExtraBits)
	}
}

func TestObservePressureRaisesDifficultyPerLevel(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		level string
		want  int
	}{
		{level: "normal", want: 16},
		{level: "elevated", want: 16 + elevatedExtraBits},
		{level: "high", want: 16 + highExtraBits},
		{level: "critical", want: 16 + criticalExtraBits},
	}
	for _, tt := range tests {
		controller := NewController(16, 24, 5*time.Minute)
		controller.now = func() time.Time { return now }
		controller.ObservePressure(tt.level)
		if got := controller.Snapshot(); got != tt.want {
			t.Fatalf("Snapshot() after pressure %q = %d, want %d", tt.level, got, tt.want)
		}
	}
}

func TestExtraBitsForAII(t *testing.T) {
	tests := []struct {
		aii  float64
		want int
	}{
		{aii: 100, want: 0},
		{aii: 109, want: 0},
		{aii: 150, want: elevatedExtraBits},
		{aii: 200, want: elevatedExtraBits},
		{aii: 250, want: criticalExtraBits},
	}
	for _, tt := range tests {
		if got := extraBitsFor(tt.aii); got != tt.want {
			t.Fatalf("extraBitsFor(%v) = %d, want %d", tt.aii, got, tt.want)
		}
	}
}

func TestDecayRisesImmediatelyAndFallsExponentially(t *testing.T) {
	// Monte immédiatement vers la cible.
	if got := decay(0, 8, time.Minute, 5*time.Minute); got != 8 {
		t.Fatalf("decay up = %v, want 8 (immediate rise)", got)
	}
	// Redescend partiellement après τ (facteur e^-1 ≈ 0.368).
	got := decay(8, 0, 5*time.Minute, 5*time.Minute)
	if got < 2.5 || got > 3.5 {
		t.Fatalf("decay after tau = %v, want ~2.94 (8*e^-1)", got)
	}
}

func TestControllerRaisesDifficultyUnderAttackThenDecays(t *testing.T) {
	now := time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC)
	controller := NewController(16, 24, 5*time.Minute)
	controller.now = func() time.Time { return now }

	// Établit une baseline basse : une requête par seconde pendant 20 s.
	for range 20 {
		controller.Observe()
		now = now.Add(time.Second)
	}
	controller.Observe()
	if d := controller.Difficulty(); d != 16 {
		t.Fatalf("baseline difficulty = %d, want 16", d)
	}

	// Pic d'attaque : beaucoup de requêtes sur la même seconde.
	for range 2000 {
		controller.Observe()
	}
	if d := controller.Difficulty(); d <= 16 {
		t.Fatalf("attack difficulty = %d, want > 16", d)
	}

	// Snapshot ne fait pas avancer la décroissance.
	before := controller.Snapshot()
	if after := controller.Snapshot(); after != before {
		t.Fatalf("snapshot mutated state: %d -> %d", before, after)
	}
}

// adaptive-protection.feature, « Retour à la normale » : les bits ajoutés
// décroissent en e^(-t/τ) — 16 + round(8·e^(-60/300)) = 23 après une minute,
// la base après 5τ.
func TestControllerDecaysBackToBaseline(t *testing.T) {
	now := time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC)
	controller := NewController(16, 24, 5*time.Minute)
	controller.now = func() time.Time { return now }
	controller.ObservePressure("critical")
	if d := controller.Snapshot(); d != 24 {
		t.Fatalf("critical difficulty = %d, want 24", d)
	}

	now = now.Add(time.Minute)
	if d := controller.Difficulty(); d != 23 {
		t.Fatalf("difficulty after 1 min = %d, want 23", d)
	}
	now = now.Add(24 * time.Minute)
	if d := controller.Difficulty(); d != 16 {
		t.Fatalf("difficulty after 5 tau = %d, want 16", d)
	}
}

// Le débit ne compte que les windowSeconds dernières secondes : une seconde
// échue, même revenue sur la même case de l'anneau, n'est plus comptée.
func TestControllerRateCountsOnlyTheWindow(t *testing.T) {
	now := time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC)
	controller := NewController(16, 24, 5*time.Minute)
	controller.now = func() time.Time { return now }

	for range 50 {
		controller.Observe()
	}
	if got := controller.rate(now.Unix()); got != 5 {
		t.Fatalf("rate = %v, want 5 (50 requests over %d s)", got, windowSeconds)
	}
	now = now.Add(windowSeconds * time.Second) // même case, seconde échue
	if got := controller.rate(now.Unix()); got != 0 {
		t.Fatalf("rate after the window = %v, want 0", got)
	}
	controller.Observe()
	if got := controller.rate(now.Unix()); got != 0.1 {
		t.Fatalf("rate = %v, want 0.1 (the reused slot restarts at 1)", got)
	}
}

// Observe retourne la difficulté de Snapshot, sous le même verrou.
func TestObserveReturnsTheSnapshotDifficulty(t *testing.T) {
	controller := NewController(16, 24, 5*time.Minute)
	controller.ObservePressure("high")
	if got, want := controller.Observe(), controller.Snapshot(); got != want || got != 22 {
		t.Fatalf("Observe() = %d, Snapshot() = %d, want both 22", got, want)
	}
}

func BenchmarkObserve(b *testing.B) {
	controller := NewController(16, 24, 5*time.Minute)
	b.ReportAllocs()
	for b.Loop() {
		controller.Observe()
	}
}

// wiredRequest reproduit l'ordre des appels du pipeline (cmd/waf) : le
// middleware anti-DDoS publie la pression (ObservePressure), le détecteur
// adaptatif compte la requête (Observe), puis le challenge lit la difficulté
// quand il sert une page (Difficulty).
func wiredRequest(controller *Controller, pressure string, servesChallenge bool) int {
	controller.ObservePressure(pressure)
	difficulty := controller.Observe()
	if servesChallenge {
		difficulty = controller.Difficulty()
	}
	return difficulty
}

// FR-14 : après l'attaque, la difficulté revient à la base par décroissance
// exponentielle, même si chaque requête publie la pression. ObservePressure
// remettait lastDecay à zéro à chaque requête : 24 bits après 30 min de trafic
// normal, alors que les tests du contrôleur seul passaient.
func TestWiredDifficultyDecaysAfterAttack(t *testing.T) {
	now := time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC)
	controller := NewController(16, 24, 5*time.Minute)
	controller.now = func() time.Time { return now }

	for range 60 {
		wiredRequest(controller, "critical", true)
		now = now.Add(100 * time.Millisecond)
	}
	if d := controller.Snapshot(); d != 24 {
		t.Fatalf("difficulty under critical pressure = %d, want 24", d)
	}

	// 30 min de trafic normal, 2 req/s, un challenge servi toutes les 10 s.
	for i := range 3600 {
		wiredRequest(controller, "normal", i%20 == 0)
		now = now.Add(500 * time.Millisecond)
	}
	if d := controller.Difficulty(); d != 16 {
		t.Fatalf("difficulty after 30 min of normal traffic = %d, want 16", d)
	}
}

// Sans challenge servi pendant la décroissance, la difficulté du premier
// challenge suivant a tout de même décru.
func TestWiredDifficultyDecaysWithoutChallengesServed(t *testing.T) {
	now := time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC)
	controller := NewController(16, 24, 5*time.Minute)
	controller.now = func() time.Time { return now }
	wiredRequest(controller, "critical", true)

	for range 1800 {
		wiredRequest(controller, "normal", false)
		now = now.Add(time.Second)
	}
	if d := controller.Difficulty(); d != 16 {
		t.Fatalf("difficulty = %d, want 16", d)
	}
}

// La baseline suit le temps écoulé, pas le nombre de challenges servis : un
// flood soutenu reste une attaque pendant des minutes. Mise à jour à chaque
// challenge (α = 0,05), elle rejoignait 500 req/s en une dizaine de secondes.
func TestBaselineDoesNotAbsorbASustainedFlood(t *testing.T) {
	now := time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC)
	controller := NewController(16, 24, 5*time.Minute)
	controller.now = func() time.Time { return now }

	// 1 h de trafic normal à 10 req/s.
	for range 3600 * 10 {
		wiredRequest(controller, "normal", false)
		now = now.Add(100 * time.Millisecond)
	}
	if d := controller.Difficulty(); d != 16 {
		t.Fatalf("difficulty at nominal traffic = %d, want 16", d)
	}

	// Flood à 500 req/s, chaque requête reçoit un challenge, pendant 5 min.
	for range 300 * 500 {
		wiredRequest(controller, "normal", true)
		now = now.Add(2 * time.Millisecond)
	}
	if d := controller.Difficulty(); d != 24 {
		t.Fatalf("difficulty after 5 min of flood = %d, want 24 (baseline %.1f req/s)", d, controller.baseline)
	}
}

// Une période sans trafic fait décroître la baseline : le premier pic qui suit
// n'est pas mesuré contre le débit d'avant le silence.
func TestBaselineDecaysOverIdleSeconds(t *testing.T) {
	now := time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC)
	controller := NewController(16, 24, 5*time.Minute)
	controller.now = func() time.Time { return now }
	for range 3600 * 10 {
		controller.Observe()
		now = now.Add(100 * time.Millisecond)
	}
	before := controller.baseline

	now = now.Add(time.Hour)
	controller.Observe()
	now = now.Add(time.Second)
	controller.Observe()
	if after := controller.baseline; after > before*0.4 || after < before*0.3 {
		t.Fatalf("baseline after 1 h idle = %.2f, want ~%.2f (e^-1 of %.2f)", after, before*0.368, before)
	}
}

// Au démarrage, la baseline n'a pas d'historique : le premier trafic n'est pas
// pris pour une attaque.
func TestNoAdaptiveRiseBeforeBaselineWarmup(t *testing.T) {
	now := time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC)
	controller := NewController(16, 24, 5*time.Minute)
	controller.now = func() time.Time { return now }
	for range 50 {
		wiredRequest(controller, "normal", true)
	}
	if d := controller.Difficulty(); d != 16 {
		t.Fatalf("startup difficulty = %d, want 16", d)
	}
}
