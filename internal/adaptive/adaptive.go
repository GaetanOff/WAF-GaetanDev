// Package adaptive ajuste dynamiquement la difficulté du proof-of-work selon
// l'intensité de l'attaque courante (FR-14, ADR-010). La difficulté monte
// immédiatement face à un pic de trafic et redescend par décroissance
// exponentielle (τ par défaut = 300 s) une fois l'attaque passée.
package adaptive

import (
	"math"
	"sync"
	"time"
)

const (
	windowSeconds = 10

	// Bits supplémentaires par niveau d'intensité (FR-14).
	elevatedExtraBits = 4
	highExtraBits     = 6
	criticalExtraBits = 8

	// Seuils de l'Attack Intensity Indicator (AII = rate courant / baseline %).
	elevatedThreshold = 110
	criticalThreshold = 200
)

// Controller calcule la difficulté courante du PoW à partir du débit observé.
type Controller struct {
	baseDifficulty int
	maxDifficulty  int
	tau            time.Duration

	mu          sync.Mutex
	counts      map[int64]int
	baseline    float64
	currentBits float64
	lastDecay   time.Time
	now         func() time.Time
}

func NewController(baseDifficulty int, maxDifficulty int, tau time.Duration) *Controller {
	if maxDifficulty < baseDifficulty {
		maxDifficulty = baseDifficulty
	}
	if tau <= 0 {
		tau = 5 * time.Minute
	}
	return &Controller{
		baseDifficulty: baseDifficulty,
		maxDifficulty:  maxDifficulty,
		tau:            tau,
		counts:         make(map[int64]int),
		now:            time.Now,
	}
}

// Observe enregistre une requête dans la fenêtre glissante courante.
func (c *Controller) Observe() {
	c.mu.Lock()
	defer c.mu.Unlock()
	sec := c.now().Unix()
	c.counts[sec]++
	c.prune(sec)
}

// ObservePressure applique immédiatement un plancher de difficulté selon la
// pression globale anti-DDoS calculée en amont.
func (c *Controller) ObservePressure(level string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	target := float64(extraBitsForPressure(level))
	if target > c.currentBits {
		c.currentBits = target
	}
	c.lastDecay = c.now()
}

// Difficulty retourne la difficulté courante du PoW [base..max].
func (c *Controller) Difficulty() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	sec := now.Unix()
	c.prune(sec)

	rate := c.rate()
	// Baseline EMA : suit lentement le débit "normal".
	if c.baseline == 0 {
		c.baseline = rate
	} else {
		c.baseline = 0.05*rate + 0.95*c.baseline
	}

	target := float64(extraBitsFor(aii(rate, c.baseline)))
	c.currentBits = decay(c.currentBits, target, now.Sub(c.lastDecay), c.tau)
	c.lastDecay = now

	difficulty := min(c.baseDifficulty+int(math.Round(c.currentBits)), c.maxDifficulty)
	if difficulty < c.baseDifficulty {
		difficulty = c.baseDifficulty
	}
	return difficulty
}

// Snapshot retourne la difficulté courante sans faire avancer la décroissance
// (lecture seule, pour l'exposition métrique).
func (c *Controller) Snapshot() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	difficulty := min(c.baseDifficulty+int(math.Round(c.currentBits)), c.maxDifficulty)
	if difficulty < c.baseDifficulty {
		difficulty = c.baseDifficulty
	}
	return difficulty
}

func (c *Controller) rate() float64 {
	total := 0
	for _, n := range c.counts {
		total += n
	}
	return float64(total) / float64(windowSeconds)
}

func (c *Controller) prune(sec int64) {
	for s := range c.counts {
		if s <= sec-windowSeconds {
			delete(c.counts, s)
		}
	}
}

// aii calcule l'Attack Intensity Indicator en pourcentage de la baseline.
func aii(rate float64, baseline float64) float64 {
	if baseline < 1 {
		baseline = 1
	}
	return rate / baseline * 100
}

// extraBitsFor mappe l'AII vers les bits supplémentaires (FR-14).
func extraBitsFor(aiiPercent float64) int {
	switch {
	case aiiPercent > criticalThreshold:
		return criticalExtraBits
	case aiiPercent > elevatedThreshold:
		return elevatedExtraBits
	default:
		return 0
	}
}

// extraBitsForPressure mappe les quatre niveaux de pression globale anti-DDoS
// (FR-08 v2) vers un plancher de bits supplémentaires distinct par niveau.
func extraBitsForPressure(level string) int {
	switch level {
	case "critical":
		return criticalExtraBits
	case "high":
		return highExtraBits
	case "elevated":
		return elevatedExtraBits
	default:
		return 0
	}
}

// decay fait monter la difficulté immédiatement vers la cible, mais la fait
// redescendre par décroissance exponentielle (τ).
func decay(current float64, target float64, elapsed time.Duration, tau time.Duration) float64 {
	if target >= current {
		return target
	}
	factor := math.Exp(-elapsed.Seconds() / tau.Seconds())
	return target + (current-target)*factor
}
