package upstream

import "testing"

func TestRoundRobinCyclesHealthyUpstreams(t *testing.T) {
	pool := NewPool(StrategyRoundRobin, []*Upstream{
		{Address: "a"}, {Address: "b"}, {Address: "c"},
	})
	seen := map[string]int{}
	for i := 0; i < 6; i++ {
		u, ok := pool.Pick("")
		if !ok {
			t.Fatal("expected a healthy upstream")
		}
		seen[u.Address]++
	}
	for _, addr := range []string{"a", "b", "c"} {
		if seen[addr] != 2 {
			t.Fatalf("upstream %s picked %d times, want 2", addr, seen[addr])
		}
	}
}

func TestUnhealthyUpstreamExcluded(t *testing.T) {
	pool := NewPool(StrategyRoundRobin, []*Upstream{{Address: "a"}, {Address: "b"}})
	pool.Upstreams()[0].SetHealthy(false)
	for i := 0; i < 4; i++ {
		u, ok := pool.Pick("")
		if !ok || u.Address != "b" {
			t.Fatalf("pick = %v ok=%v, want only b", u, ok)
		}
	}
}

func TestBackupUsedWhenPrimariesDown(t *testing.T) {
	pool := NewPool(StrategyRoundRobin, []*Upstream{
		{Address: "primary"},
		{Address: "backup", Backup: true},
	})
	// Primaire sain → backup non utilisé.
	if u, _ := pool.Pick(""); u.Address != "primary" {
		t.Fatalf("pick = %s, want primary", u.Address)
	}
	// Primaire down → bascule sur backup.
	pool.Upstreams()[0].SetHealthy(false)
	if u, ok := pool.Pick(""); !ok || u.Address != "backup" {
		t.Fatalf("pick = %v ok=%v, want backup", u, ok)
	}
}

func TestAllDownReturnsFalse(t *testing.T) {
	pool := NewPool(StrategyRoundRobin, []*Upstream{{Address: "a"}})
	pool.Upstreams()[0].SetHealthy(false)
	if _, ok := pool.Pick(""); ok {
		t.Fatal("expected no healthy upstream")
	}
}

func TestIPHashIsStable(t *testing.T) {
	pool := NewPool(StrategyIPHash, []*Upstream{{Address: "a"}, {Address: "b"}, {Address: "c"}})
	first, _ := pool.Pick("1.2.3.4")
	for i := 0; i < 5; i++ {
		u, _ := pool.Pick("1.2.3.4")
		if u.Address != first.Address {
			t.Fatalf("ip_hash not stable: %s vs %s", u.Address, first.Address)
		}
	}
}

func TestLeastConnPicksFewestInflight(t *testing.T) {
	pool := NewPool(StrategyLeastConn, []*Upstream{{Address: "a"}, {Address: "b"}})
	pool.Upstreams()[0].Acquire()
	pool.Upstreams()[0].Acquire() // a a 2 connexions, b 0
	if u, _ := pool.Pick(""); u.Address != "b" {
		t.Fatalf("least_conn pick = %s, want b", u.Address)
	}
}

func TestWeightedFavorsHigherWeight(t *testing.T) {
	pool := NewPool(StrategyWeighted, []*Upstream{
		{Address: "a", Weight: 3},
		{Address: "b", Weight: 1},
	})
	seen := map[string]int{}
	for i := 0; i < 4; i++ {
		u, _ := pool.Pick("")
		seen[u.Address]++
	}
	if seen["a"] != 3 || seen["b"] != 1 {
		t.Fatalf("weighted distribution = %v, want a:3 b:1", seen)
	}
}
