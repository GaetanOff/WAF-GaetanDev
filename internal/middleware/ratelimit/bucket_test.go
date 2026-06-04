package ratelimit

import (
	"testing"
	"time"
)

func TestTokenBucketAllowsBurst(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	bucket := NewTokenBucket(50, 100, now)

	for i := 0; i < 100; i++ {
		allowed, _ := bucket.TryConsume(now)
		if !allowed {
			t.Fatalf("request %d denied, want allowed", i+1)
		}
	}

	allowed, retryAfter := bucket.TryConsume(now)
	if allowed {
		t.Fatal("expected burst overflow to be denied")
	}
	if retryAfter <= 0 {
		t.Fatalf("retryAfter = %s, want positive", retryAfter)
	}
}

func TestTokenBucketRefillsAfterOneSecond(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	bucket := NewTokenBucket(1, 1, now)

	allowed, _ := bucket.TryConsume(now)
	if !allowed {
		t.Fatal("first request should be allowed")
	}
	allowed, _ = bucket.TryConsume(now)
	if allowed {
		t.Fatal("second immediate request should be denied")
	}
	allowed, _ = bucket.TryConsume(now.Add(time.Second))
	if !allowed {
		t.Fatal("request after refill should be allowed")
	}
}
