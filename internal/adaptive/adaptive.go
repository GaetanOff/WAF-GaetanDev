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

	// baselineSeconds est la constante de temps de la baseline : une moyenne
	// exponentielle du débit par seconde écoulée, cumulée pendant sa première
	// période. Mise à jour à chaque challenge servi (α = 0,05), elle rejoignait
	// un flood soutenu en une dizaine de secondes et annulait la difficulté
	// ajoutée pendant l'attaque même.
	baselineSeconds = 3600
)

// Controller calcule la difficulté courante du PoW à partir du débit observé.
type Controller struct {
	baseDifficulty int
	maxDifficulty  int
	tau            time.Duration

	mu sync.Mutex
	// counts compte les requêtes des windowSeconds dernières secondes, une case
	// par seconde (seconde modulo windowSeconds). Une map, parcourue en entier
	// à chaque requête pour purger les secondes échues, tenait ce rôle.
	counts [windowSeconds]secondCount
	// baseline est le débit « normal » (req/s) ; baselineSamples le nombre de
	// secondes qu'elle résume (borné à baselineSeconds). curSec et curCount
	// comptent la seconde en cours, versée à la baseline quand elle s'achève.
	baseline        float64
	baselineSamples int64
	curSec          int64
	curCount        int
	// currentBits est la difficulté ajoutée : elle monte immédiatement vers la
	// cible de l'AII et redescend en e^(-t/τ) depuis lastDecay.
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
		now:            time.Now,
	}
}

// SetBaseDifficulty applique à chaud la difficulté de base
// (challenge.pow_difficulty, PATCH /waf/admin/config). Le plafond suit si la
// nouvelle base le dépasse.
func (c *Controller) SetBaseDifficulty(base int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.baseDifficulty = base
	if c.maxDifficulty < base {
		c.maxDifficulty = base
	}
}

// secondCount est le nombre de requêtes observées pendant la seconde sec.
type secondCount struct {
	sec int64
	n   int
}

// Observe enregistre une requête dans la fenêtre glissante courante et
// retourne la difficulté courante, sans faire avancer la décroissance (valeur
// de Snapshot) : un seul verrou par requête là où Observe puis Snapshot en
// prenaient deux.
func (c *Controller) Observe() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	sec := c.now().Unix()
	slot := &c.counts[uint64(sec)%windowSeconds]
	if slot.sec != sec {
		slot.sec, slot.n = sec, 0
	}
	slot.n++
	c.countForBaseline(sec)
	return c.snapshotLocked()
}

// countForBaseline compte la requête dans la seconde en cours ; la seconde
// précédente, achevée, est versée à la baseline, suivie des secondes sans
// requête qui les séparent.
func (c *Controller) countForBaseline(sec int64) {
	if sec != c.curSec {
		if c.curSec != 0 {
			c.feedBaseline(float64(c.curCount), max(sec-c.curSec-1, 0))
		}
		c.curSec, c.curCount = sec, 0
	}
	c.curCount++
}

// feedBaseline verse une seconde de count requêtes puis idle secondes vides.
// Pendant ses baselineSeconds premières secondes, la baseline est leur moyenne
// cumulée ; ensuite, une moyenne exponentielle de constante baselineSeconds.
func (c *Controller) feedBaseline(count float64, idle int64) {
	c.baselineSamples = min(c.baselineSamples+1, baselineSeconds)
	c.baseline += (count - c.baseline) / float64(c.baselineSamples)
	if idle <= 0 {
		return
	}
	if warmup := min(idle, baselineSeconds-c.baselineSamples); warmup > 0 {
		c.baseline *= float64(c.baselineSamples) / float64(c.baselineSamples+warmup)
		c.baselineSamples += warmup
		idle -= warmup
	}
	c.baseline *= math.Exp(-float64(idle) / baselineSeconds)
}

// ObservePressure applique immédiatement un plancher de difficulté selon la
// pression globale anti-DDoS calculée en amont. Appelée à chaque requête, elle
// fait d'abord avancer la décroissance : elle remettait lastDecay à l'instant
// courant sans rien décroître, et la difficulté ne redescendait jamais tant
// que le trafic continuait (FR-14).
func (c *Controller) ObservePressure(level string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.advanceLocked(c.now())
	if floor := float64(extraBitsForPressure(level)); floor > c.currentBits {
		c.currentBits = floor
	}
}

// advanceLocked fait tendre currentBits vers la cible de l'AII courant sur le
// temps écoulé depuis lastDecay.
func (c *Controller) advanceLocked(now time.Time) {
	target := 0.0
	// Sans windowSeconds d'historique, la baseline ne dit encore rien : tout
	// trafic de démarrage passerait pour une attaque.
	if c.baselineSamples >= windowSeconds {
		target = float64(extraBitsFor(aii(c.rate(now.Unix()), c.baseline)))
	}
	if c.lastDecay.IsZero() {
		c.currentBits = max(c.currentBits, target)
	} else {
		c.currentBits = decay(c.currentBits, target, now.Sub(c.lastDecay), c.tau)
	}
	c.lastDecay = now
}

// Difficulty retourne la difficulté courante du PoW [base..max].
func (c *Controller) Difficulty() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.advanceLocked(c.now())

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
	return c.snapshotLocked()
}

func (c *Controller) snapshotLocked() int {
	difficulty := min(c.baseDifficulty+int(math.Round(c.currentBits)), c.maxDifficulty)
	if difficulty < c.baseDifficulty {
		difficulty = c.baseDifficulty
	}
	return difficulty
}

// rate est le débit moyen des windowSeconds secondes qui précèdent sec ; une
// case d'une seconde échue n'est pas comptée.
func (c *Controller) rate(sec int64) float64 {
	total := 0
	for _, slot := range c.counts {
		if slot.sec > sec-windowSeconds {
			total += slot.n
		}
	}
	return float64(total) / float64(windowSeconds)
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
