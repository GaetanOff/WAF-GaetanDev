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

func TestStoreEvictsLeastRecentlyUsedVisitor(t *testing.T) {
	store := New(2)
	t.Cleanup(store.Close)

	expiresAt := time.Now().Add(time.Hour)
	store.SetVisitor("a", storage.VisitorState{IPHash: "a", ExpiresAt: expiresAt})
	store.SetVisitor("b", storage.VisitorState{IPHash: "b", ExpiresAt: expiresAt})
	if _, ok := store.GetVisitor("a"); !ok {
		t.Fatal("expected visitor a")
	}
	store.SetVisitor("c", storage.VisitorState{IPHash: "c", ExpiresAt: expiresAt})

	if _, ok := store.GetVisitor("b"); ok {
		t.Fatal("expected visitor b to be evicted")
	}
	if _, ok := store.GetVisitor("a"); !ok {
		t.Fatal("expected recently used visitor a to remain")
	}
	if _, ok := store.GetVisitor("c"); !ok {
		t.Fatal("expected visitor c")
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
