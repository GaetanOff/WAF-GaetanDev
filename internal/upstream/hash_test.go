package upstream

import (
	"hash/fnv"
	"testing"
)

// hashKey calcule FNV-1a 32 bits en place : la répartition par affinité
// (ip_hash) doit rester celle de hash/fnv.
func TestHashKeyMatchesFNV1a(t *testing.T) {
	for _, key := range []string{"", "a", "203.0.113.42", "2001:db8::/64", "héllo"} {
		reference := fnv.New32a()
		_, _ = reference.Write([]byte(key))
		if got, want := hashKey(key), reference.Sum32(); got != want {
			t.Errorf("hashKey(%q) = %d, want %d", key, got, want)
		}
	}
}
