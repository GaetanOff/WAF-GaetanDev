package upstream

import "testing"

// Chemin chaud de chaque requête proxifiée par le pool : aucune allocation.
func BenchmarkPoolPick(b *testing.B) {
	for _, strategy := range []string{StrategyRoundRobin, StrategyIPHash, StrategyLeastConn, StrategyWeighted} {
		b.Run(strategy, func(b *testing.B) {
			pool := NewPool(strategy, fiveUpstreams())
			b.ReportAllocs()
			for b.Loop() {
				pool.Pick("203.0.113.10")
			}
		})
	}
}

func TestPoolPickDoesNotAllocate(t *testing.T) {
	for _, strategy := range []string{StrategyRoundRobin, StrategyIPHash, StrategyLeastConn, StrategyWeighted} {
		pool := NewPool(strategy, fiveUpstreams())
		if allocs := testing.AllocsPerRun(100, func() { pool.Pick("203.0.113.10") }); allocs != 0 {
			t.Fatalf("%s: %v allocations per Pick, want 0", strategy, allocs)
		}
	}
}

func fiveUpstreams() []*Upstream {
	return []*Upstream{{Address: "a"}, {Address: "b", Weight: 3}, {Address: "c"}, {Address: "d"}, {Address: "e", Backup: true}}
}

// Le compteur de rotation est partagé par toutes les requêtes concurrentes.
func BenchmarkPoolPickParallel(b *testing.B) {
	pool := NewPool(StrategyRoundRobin, fiveUpstreams())
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pool.Pick("203.0.113.10")
		}
	})
}
