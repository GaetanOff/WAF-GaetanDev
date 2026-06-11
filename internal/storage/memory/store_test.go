package memory

import (
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/storage"
)

func TestStoreGetSetDeleteVisitor(t *testing.T) {
	store := New(10)
	t.Cleanup(store.Close)

	expiresAt := time.Now().Add(time.Hour)
	store.SetVisitor("ip:domain", storage.VisitorState{IPHash: "abc", Domain: "example.com", Score: 50, ExpiresAt: expiresAt})

	visitor, ok := store.GetVisitor("ip:domain")
	if !ok {
		t.Fatal("expected visitor")
	}
	if visitor.Score != 50 {
		t.Fatalf("Score = %d, want 50", visitor.Score)
	}

	store.DeleteVisitor("ip:domain")
	if _, ok := store.GetVisitor("ip:domain"); ok {
		t.Fatal("expected visitor to be deleted")
	}
}

func TestStoreExpiresVisitorAndBucket(t *testing.T) {
	store := New(10)
	t.Cleanup(store.Close)

	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	store.SetVisitor("visitor", storage.VisitorState{ExpiresAt: now.Add(-time.Second)})
	store.SetBucket("bucket", storage.RateBucket{ExpiresAt: now.Add(-time.Second)})

	if _, ok := store.GetVisitor("visitor"); ok {
		t.Fatal("expected expired visitor to be absent")
	}
	if _, ok := store.GetBucket("bucket"); ok {
		t.Fatal("expected expired bucket to be absent")
	}
}

func TestStoreEvictsLeastRecentlySetVisitor(t *testing.T) {
	store := New(2)
	t.Cleanup(store.Close)

	expiresAt := time.Now().Add(time.Hour)
	store.SetVisitor("a", storage.VisitorState{IPHash: "a", ExpiresAt: expiresAt})
	store.SetVisitor("b", storage.VisitorState{IPHash: "b", ExpiresAt: expiresAt})
	// Les lectures ne « touchent » plus la LRU (lecture lock-free) : on rafraîchit
	// "a" via un nouveau SetVisitor (chemin réel : Apply réécrit le visiteur actif).
	store.SetVisitor("a", storage.VisitorState{IPHash: "a", Score: 60, ExpiresAt: expiresAt})
	store.SetVisitor("c", storage.VisitorState{IPHash: "c", ExpiresAt: expiresAt})

	if _, ok := store.GetVisitor("b"); ok {
		t.Fatal("expected least-recently-set visitor b to be evicted")
	}
	if _, ok := store.GetVisitor("a"); !ok {
		t.Fatal("expected recently set visitor a to remain")
	}
	if _, ok := store.GetVisitor("c"); !ok {
		t.Fatal("expected visitor c")
	}
}

func TestCleanupExpiredRemovesExpiredKeepsLive(t *testing.T) {
	store := New(100)
	t.Cleanup(store.Close)
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	store.SetVisitor("live", storage.VisitorState{IPHash: "live", ExpiresAt: now.Add(time.Hour)})
	store.SetVisitor("dead", storage.VisitorState{IPHash: "dead", ExpiresAt: now.Add(time.Minute)})
	store.SetBucket("live-b", storage.RateBucket{IPHash: "live-b", ExpiresAt: now.Add(time.Hour)})
	store.SetBucket("dead-b", storage.RateBucket{IPHash: "dead-b", ExpiresAt: now.Add(time.Minute)})

	store.now = func() time.Time { return now.Add(10 * time.Minute) }
	store.CleanupExpired()

	if _, ok := store.GetVisitor("live"); !ok {
		t.Fatal("live visitor must be kept")
	}
	if _, ok := store.GetVisitor("dead"); ok {
		t.Fatal("expired visitor must be removed")
	}
	if _, ok := store.GetBucket("live-b"); !ok {
		t.Fatal("live bucket must be kept")
	}
	if _, ok := store.GetBucket("dead-b"); ok {
		t.Fatal("expired bucket must be removed")
	}
}

func TestCleanupBoundsBucketCount(t *testing.T) {
	store := New(2) // borne = 2 buckets
	t.Cleanup(store.Close)
	base := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }

	// 4 buckets vivants, LastRefill croissant : old1 (le plus ancien) → new2.
	order := []string{"old1", "old2", "new1", "new2"}
	for i, key := range order {
		store.SetBucket(key, storage.RateBucket{
			IPHash:     key,
			LastRefill: base.Add(time.Duration(i) * time.Minute),
			ExpiresAt:  base.Add(time.Hour),
		})
	}

	store.CleanupExpired()

	for _, key := range []string{"new1", "new2"} {
		if _, ok := store.GetBucket(key); !ok {
			t.Fatalf("recent bucket %q must survive the cap", key)
		}
	}
	for _, key := range []string{"old1", "old2"} {
		if _, ok := store.GetBucket(key); ok {
			t.Fatalf("oldest bucket %q must be evicted by the cap", key)
		}
	}
}

func TestStoreGetSetBucket(t *testing.T) {
	store := New(10)
	t.Cleanup(store.Close)

	store.SetBucket("bucket", storage.RateBucket{Tokens: 10, ExpiresAt: time.Now().Add(time.Hour)})
	bucket, ok := store.GetBucket("bucket")
	if !ok {
		t.Fatal("expected bucket")
	}
	if bucket.Tokens != 10 {
		t.Fatalf("Tokens = %f, want 10", bucket.Tokens)
	}
}
