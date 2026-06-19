package antiddos

import (
	"testing"
	"time"
)

func newTestUnderAttack(cfg UnderAttackConfig, now *time.Time) *UnderAttackDetector {
	d := NewUnderAttackDetector(cfg)
	d.now = func() time.Time { return *now }
	return d
}

// TestUnderAttackHysteresis vérifie la machine à états : entrée à trigger_pressure,
// maintien sous tension, et sortie seulement après exit_pressure soutenu cooldown.
func TestUnderAttackHysteresis(t *testing.T) {
	now := time.Now()
	d := NewUnderAttackDetector(UnderAttackConfig{
		Enabled:         true,
		TriggerPressure: PressureHigh,
		ExitPressure:    PressureElevated,
		Cooldown:        30 * time.Second,
	})
	d.now = func() time.Time { return now }
	st := &scopeState{}

	if d.evaluateLocked(st, PressureElevated) {
		t.Fatal("elevated < trigger high: ne doit pas activer")
	}
	if !d.evaluateLocked(st, PressureHigh) {
		t.Fatal("high >= trigger: doit activer")
	}
	// Retombée à elevated (<= exit) : démarre le cooldown mais reste actif.
	if !d.evaluateLocked(st, PressureElevated) {
		t.Fatal("doit rester actif tant que cooldown non écoulé")
	}
	now = now.Add(20 * time.Second)
	if !d.evaluateLocked(st, PressureNormal) {
		t.Fatal("20s < cooldown 30s: doit rester actif")
	}
	// Re-pic à high : réarme le timer (toujours sous tension).
	if !d.evaluateLocked(st, PressureHigh) {
		t.Fatal("re-pic high: doit rester actif et réarmer")
	}
	if !d.evaluateLocked(st, PressureElevated) {
		t.Fatal("retombée: actif, redémarre le cooldown")
	}
	now = now.Add(31 * time.Second)
	if d.evaluateLocked(st, PressureNormal) {
		t.Fatal("exit_pressure soutenu > cooldown: doit sortir")
	}
}

// TestUnderAttackObserveAndShadow vérifie le déclenchement par la pression réelle et
// le comportement shadow (état journalisé, mais enforcement désactivé).
func TestUnderAttackObserveAndShadow(t *testing.T) {
	for _, shadow := range []bool{false, true} {
		now := time.Now()
		d := newTestUnderAttack(UnderAttackConfig{
			Enabled:         true,
			PerDomain:       true,
			TriggerPressure: PressureHigh,
			ExitPressure:    PressureElevated,
			Cooldown:        30 * time.Second,
			Shadow:          shadow,
			Threshold:       1,
			Window:          time.Second,
		}, &now)

		first := d.Observe("a.test")
		if first.UnderAttack {
			t.Fatalf("shadow=%v: 1 requête (elevated) ne doit pas déclencher", shadow)
		}
		second := d.Observe("a.test")
		if !second.UnderAttack {
			t.Fatalf("shadow=%v: 2 requêtes (high) doivent déclencher", shadow)
		}
		if second.Enforce == shadow {
			t.Fatalf("shadow=%v: Enforce=%v attendu %v", shadow, second.Enforce, !shadow)
		}
	}
}

// TestUnderAttackPerDomainIsolation : un flood sur un domaine ne met pas un autre
// domaine en mode sous attaque (scope per_domain).
func TestUnderAttackPerDomainIsolation(t *testing.T) {
	now := time.Now()
	d := newTestUnderAttack(UnderAttackConfig{
		Enabled:         true,
		PerDomain:       true,
		TriggerPressure: PressureHigh,
		ExitPressure:    PressureElevated,
		Cooldown:        30 * time.Second,
		Threshold:       1,
		Window:          time.Second,
	}, &now)

	d.Observe("flood.test")
	attacked := d.Observe("flood.test")
	if !attacked.UnderAttack {
		t.Fatal("le domaine floodé doit être en mode sous attaque")
	}
	calm := d.Observe("calm.test")
	if calm.UnderAttack {
		t.Fatal("un autre domaine ne doit pas être affecté (scope per_domain)")
	}
}

// TestUnderAttackGlobalScope : en scope global, tous les domaines partagent le même
// compteur, et le mode s'applique à tout le trafic.
func TestUnderAttackGlobalScope(t *testing.T) {
	now := time.Now()
	d := newTestUnderAttack(UnderAttackConfig{
		Enabled:         true,
		PerDomain:       false,
		TriggerPressure: PressureHigh,
		ExitPressure:    PressureElevated,
		Cooldown:        30 * time.Second,
		Threshold:       1,
		Window:          time.Second,
	}, &now)

	d.Observe("a.test")
	got := d.Observe("b.test") // deux domaines, même compteur global -> high
	if !got.UnderAttack {
		t.Fatal("scope global: le trafic cumulé doit déclencher pour tout domaine")
	}
}

// TestUnderAttackLRUEviction : le nombre de domaines suivis est borné.
func TestUnderAttackLRUEviction(t *testing.T) {
	now := time.Now()
	d := newTestUnderAttack(UnderAttackConfig{
		Enabled:    true,
		PerDomain:  true,
		Threshold:  1,
		Window:     time.Second,
		MaxDomains: 2,
	}, &now)

	d.Observe("a.test")
	d.Observe("b.test")
	d.Observe("c.test")

	d.mu.Lock()
	size := len(d.states)
	d.mu.Unlock()
	if size > 2 {
		t.Fatalf("LRU non borné: %d scopes suivis, max 2", size)
	}
}

// TestUnderAttackTransitionObserver : l'observateur est appelé à l'entrée et à la
// sortie du mode, une fois chacune.
func TestUnderAttackTransitionObserver(t *testing.T) {
	now := time.Now()
	d := newTestUnderAttack(UnderAttackConfig{
		Enabled:         true,
		PerDomain:       true,
		TriggerPressure: PressureHigh,
		ExitPressure:    PressureElevated,
		Cooldown:        30 * time.Second,
		Threshold:       1,
		Window:          time.Second,
	}, &now)

	var enters, exits int
	d.WithTransitionObserver(func(scope string, active bool) {
		if active {
			enters++
		} else {
			exits++
		}
	})

	d.Observe("x.test")
	d.Observe("x.test") // -> high -> entrée
	if enters != 1 {
		t.Fatalf("entrées = %d, want 1", enters)
	}

	// Laisse expirer la fenêtre puis dépasse le cooldown -> sortie.
	now = now.Add(2 * time.Second)
	d.Observe("x.test") // elevated (<= exit), démarre cooldown
	now = now.Add(31 * time.Second)
	d.Observe("x.test") // cooldown écoulé -> sortie
	if exits != 1 {
		t.Fatalf("sorties = %d, want 1", exits)
	}
}
