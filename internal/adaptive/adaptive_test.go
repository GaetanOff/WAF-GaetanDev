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

	// Établit une baseline basse.
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
