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
	for i := 0; i < 2000; i++ {
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
