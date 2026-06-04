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
	if rate < 1 {
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

func (b *TokenBucket) TryConsume(now time.Time) (bool, time.Duration) {
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
			currentBits = math.Float64bits(refilled)
		}

		if refilled < 1 {
			missing := 1 - refilled
			return false, time.Duration(math.Ceil(missing/b.rate)) * time.Second
		}

		remaining := refilled - 1
		if b.tokens.CompareAndSwap(currentBits, math.Float64bits(remaining)) {
			return true, 0
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
