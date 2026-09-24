package ttlcache

import (
	"strconv"
	"testing"
	"time"
)

func TestCacheEvictsLeastRecentlyUsedBeyondCapacity(t *testing.T) {
	cache := New[string, int](3, 0)
	for i := range 3 {
		cache.Set(strconv.Itoa(i), i)
	}
	cache.Get("0") // "1" devient le moins récemment utilisé
	cache.Set("3", 3)

	if cache.Len() != 3 {
		t.Fatalf("len = %d, want 3", cache.Len())
	}
	if _, ok := cache.Get("1"); ok {
		t.Fatal(`"1" should have been evicted (least recently used)`)
	}
	for _, key := range []string{"0", "2", "3"} {
		if _, ok := cache.Get(key); !ok {
			t.Fatalf("%q should still be cached", key)
		}
	}
}

func TestCacheExpiresEntries(t *testing.T) {
	now := time.Now()
	cache := New[string, int](10, time.Minute).WithClock(func() time.Time { return now })
	cache.Set("a", 1)
	cache.SetWithTTL("b", 2, time.Hour)

	now = now.Add(2 * time.Minute)
	if _, ok := cache.Get("a"); ok {
		t.Fatal(`"a" should have expired`)
	}
	if value, ok := cache.Get("b"); !ok || value != 2 {
		t.Fatalf(`"b" = %d, %v; want 2 with its own TTL`, value, ok)
	}
	if cache.Len() != 1 {
		t.Fatalf("len = %d, want 1: an expired entry read is removed", cache.Len())
	}
}

func TestCacheUpdateIsReadModifyWrite(t *testing.T) {
	cache := New[string, int](10, 0)
	for range 5 {
		cache.Update("hits", func(current int, _ bool) int { return current + 1 })
	}
	if value, _ := cache.Get("hits"); value != 5 {
		t.Fatalf("hits = %d, want 5", value)
	}
}

// La mémoire reste bornée quel que soit le nombre de clés distinctes (DDoS
// distribué sur des centaines de milliers d'IP).
func TestCacheStaysBoundedUnderManyDistinctKeys(t *testing.T) {
	cache := New[int, struct{}](1000, time.Hour)
	for i := range 200_000 {
		cache.Set(i, struct{}{})
	}
	if cache.Len() != 1000 {
		t.Fatalf("len = %d, want 1000", cache.Len())
	}
}
