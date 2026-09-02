package ratelimit

import (
	"math"
	"sync/atomic"
	"time"
)

type TokenBucket struct {
	rate     float64
	capacity float64
	tokens   atomic.Uint64
	refillNS atomic.Int64
}

func NewTokenBucket(rate float64, capacity float64, now time.Time) *TokenBucket {
	// Garde-fous contre une configuration impossible, pas contre un débit lent :
	// les fenêtres minute et heure (FR-03) rechargent volontairement à moins d'un
	// jeton par seconde (600 req/min = 10/s, 3600 req/h = 1/s, 60 req/h = 1/60 s).
	// Ramener ces débits à 1/s rendrait la fenêtre inopérante — c'est un débit
	// nul ou négatif qui est absurde (recharge jamais, division par zéro dans le
	// calcul du Retry-After), pas un débit fractionnaire.
	if rate <= 0 {
		rate = 1
	}
	if capacity < 1 {
		capacity = 1
	}

	bucket := &TokenBucket{rate: rate, capacity: capacity}
	bucket.tokens.Store(math.Float64bits(capacity))
	bucket.refillNS.Store(now.UnixNano())
	return bucket
}

// TryConsume recharge le bucket jusqu'à now puis prélève un jeton. Retourne le
// délai avant qu'un jeton soit disponible quand le bucket est vide.
func (b *TokenBucket) TryConsume(now time.Time) (bool, time.Duration) {
	for {
		allowed, retryAfter := b.Refill(now)
		if !allowed {
			return false, retryAfter
		}
		if b.Consume() {
			return true, 0
		}
		// Jeton disparu entre le constat et le prélèvement (recharge concurrente
		// sur le même bucket) : on refait le tour complet.
	}
}

// Refill recharge le bucket jusqu'à now SANS rien prélever, et indique si un
// jeton est disponible (sinon, le délai avant qu'il le soit).
//
// Séparer la recharge du prélèvement est nécessaire dès qu'une requête doit
// satisfaire plusieurs fenêtres (FR-03) : le refus d'une fenêtre ne doit pas
// consommer le jeton des autres, sinon un client bloqué par sa limite horaire
// verrait aussi son burst à la seconde vidé — et repartirait avec un bucket vide
// à la réouverture de la fenêtre.
func (b *TokenBucket) Refill(now time.Time) (bool, time.Duration) {
	for {
		currentBits := b.tokens.Load()
		currentTokens := math.Float64frombits(currentBits)
		lastRefill := time.Unix(0, b.refillNS.Load())
		elapsed := now.Sub(lastRefill).Seconds()
		refilled := minFloat(b.capacity, currentTokens+(elapsed*b.rate))

		if elapsed > 0 {
			if !b.tokens.CompareAndSwap(currentBits, math.Float64bits(refilled)) {
				continue
			}
			b.refillNS.CompareAndSwap(lastRefill.UnixNano(), now.UnixNano())
		}

		if refilled < 1 {
			missing := 1 - refilled
			return false, time.Duration(math.Ceil(missing/b.rate)) * time.Second
		}
		return true, 0
	}
}

// Consume prélève un jeton constaté disponible par Refill. Retourne false si le
// jeton a disparu entre-temps.
func (b *TokenBucket) Consume() bool {
	for {
		currentBits := b.tokens.Load()
		currentTokens := math.Float64frombits(currentBits)
		if currentTokens < 1 {
			return false
		}
		if b.tokens.CompareAndSwap(currentBits, math.Float64bits(currentTokens-1)) {
			return true
		}
	}
}

func (b *TokenBucket) Snapshot(now time.Time, ttl time.Duration, ipHash string) BucketSnapshot {
	tokens := math.Float64frombits(b.tokens.Load())
	return BucketSnapshot{
		IPHash:     ipHash,
		Tokens:     tokens,
		LastRefill: time.Unix(0, b.refillNS.Load()),
		Rate:       b.rate,
		Capacity:   b.capacity,
		ExpiresAt:  now.Add(ttl),
	}
}

type BucketSnapshot struct {
	IPHash     string
	Tokens     float64
	LastRefill time.Time
	Rate       float64
	Capacity   float64
	ExpiresAt  time.Time
}

func BucketFromSnapshot(snapshot BucketSnapshot) *TokenBucket {
	bucket := NewTokenBucket(snapshot.Rate, snapshot.Capacity, snapshot.LastRefill)
	bucket.tokens.Store(math.Float64bits(snapshot.Tokens))
	return bucket
}

func minFloat(a float64, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
