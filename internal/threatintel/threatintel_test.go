package threatintel

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/trust"
)

func TestStaticSourceReturnsWorstMatchingLevel(t *testing.T) {
	source := NewStaticSource().
		Add("10.0.0.0/8", LevelSuspect, "datacenter").
		Add("10.1.2.0/24", LevelMalicious, "blocklist")

	if v := source.Lookup(net.ParseIP("10.1.2.3")); v.Level != LevelMalicious {
		t.Fatalf("level = %d, want malicious", v.Level)
	}
	if v := source.Lookup(net.ParseIP("10.9.9.9")); v.Level != LevelSuspect {
		t.Fatalf("level = %d, want suspect", v.Level)
	}
	if v := source.Lookup(net.ParseIP("8.8.8.8")); v.Level != LevelClean {
		t.Fatalf("level = %d, want clean", v.Level)
	}
}

func TestCheckerCachesResolvedVerdict(t *testing.T) {
	source := NewStaticSource().Add("1.2.3.0/24", LevelMalicious, "blocklist")
	checker := NewChecker(time.Hour, source)

	// Premier appel : miss → clean immédiat (non bloquant).
	if v := checker.Verdict("1.2.3.4"); v.Level != LevelClean {
		t.Fatalf("first lookup level = %d, want clean (async miss)", v.Level)
	}
	// Résolution synchrone puis lecture du cache.
	checker.resolveSync("1.2.3.4")
	if v := checker.Verdict("1.2.3.4"); v.Level != LevelMalicious {
		t.Fatalf("cached level = %d, want malicious", v.Level)
	}
}

func TestMiddlewareCriticalSetsDeterministicTrigger(t *testing.T) {
	source := NewStaticSource().Add("9.9.9.0/24", LevelCritical, "abuseipdb_critical")
	checker := NewChecker(time.Hour, source)
	checker.resolveSync("9.9.9.9")
	scores, store := newScores(t)
	defer store.Close()

	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "9.9.9.9:1234"
	NewMiddleware(checker, scores).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-WAF-Deterministic-Trigger") != "threat_intel_critical" {
			t.Fatalf("trigger = %q, want threat_intel_critical", r.Header.Get("X-WAF-Deterministic-Trigger"))
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), request)
}

func TestMiddlewareMaliciousCapsTrustScore(t *testing.T) {
	source := NewStaticSource().Add("5.5.5.0/24", LevelMalicious, "blocklist")
	checker := NewChecker(time.Hour, source)
	checker.resolveSync("5.5.5.5")
	scores, store := newScores(t)
	defer store.Close()
	scores.Set("5.5.5.5", "example.test", 80)

	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "5.5.5.5:1234"
	NewMiddleware(checker, scores).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), request)

	if got := scores.Get("5.5.5.5", "example.test").Score; got > ceilingMalicious {
		t.Fatalf("score = %d, want <= %d", got, ceilingMalicious)
	}
}

func TestHTTPSourceMapsAbuseConfidenceScore(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":90}}`))
	}))
	defer server.Close()

	source := NewHTTPSource(server.URL, "test-key", server.Client())
	if v := source.Lookup(net.ParseIP("1.2.3.4")); v.Level != LevelCritical {
		t.Fatalf("level = %d, want critical for score 90", v.Level)
	}
}

func newScores(t *testing.T) (*trust.ScoreManager, *memory.Store) {
	t.Helper()
	store := memory.New(100)
	cfg := config.Default()
	cfg.Challenge.Enabled = false
	cfg.Admin.Enabled = false
	manager, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	return manager, store
}

// Régression : le cache était une map jamais purgée — chaque IP vue y restait.
func TestCheckerCacheIsBounded(t *testing.T) {
	checker := NewChecker(time.Hour, NewStaticSource())
	for i := range maxCachedVerdicts + 500 {
		checker.resolveSync(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
	}
	// Cache segmenté (ttlcache) : borné, un segment pouvant évincer avant que
	// les autres soient pleins.
	if got := checker.cache.Len(); got > maxCachedVerdicts || got < maxCachedVerdicts*98/100 {
		t.Fatalf("cached verdicts = %d, want at most %d and nearly full", got, maxCachedVerdicts)
	}
}

type blockingSource struct {
	release chan struct{}
	active  *atomic.Int64
	peak    *atomic.Int64
}

func (s blockingSource) Lookup(net.IP) Verdict {
	current := s.active.Add(1)
	for {
		peak := s.peak.Load()
		if current <= peak || s.peak.CompareAndSwap(peak, current) {
			break
		}
	}
	<-s.release
	s.active.Add(-1)
	return Verdict{Level: LevelClean}
}

// Régression : chaque miss lançait sa goroutine — un flux d'IP neuves en
// lançait autant, toutes concurrentes contre la source HTTP.
func TestCheckerBoundsConcurrentLookups(t *testing.T) {
	source := blockingSource{release: make(chan struct{}), active: new(atomic.Int64), peak: new(atomic.Int64)}
	checker := NewChecker(time.Hour, source)
	defer checker.Close()
	before := runtime.NumGoroutine()

	for i := range 5000 {
		checker.Verdict(fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
	}
	time.Sleep(50 * time.Millisecond)

	if grown := runtime.NumGoroutine() - before; grown > 0 {
		t.Fatalf("goroutines grew by %d for 5000 misses, want none beyond the fixed pool", grown)
	}
	if peak := source.peak.Load(); peak > lookupWorkers {
		t.Fatalf("concurrent lookups = %d, want <= %d", peak, lookupWorkers)
	}
	close(source.release)
}

// threat-intelligence.feature : paliers AbuseIPDB (>= 80 critique, >= 50
// malveillant, sinon propre) et service en échec traité comme « propre ».
func TestHTTPSourceScoreTiersAndFailures(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   Level
	}{
		{name: "critical", status: http.StatusOK, body: `{"data":{"abuseConfidenceScore":92}}`, want: LevelCritical},
		{name: "malicious", status: http.StatusOK, body: `{"data":{"abuseConfidenceScore":55}}`, want: LevelMalicious},
		{name: "clean", status: http.StatusOK, body: `{"data":{"abuseConfidenceScore":10}}`, want: LevelClean},
		{name: "service error", status: http.StatusServiceUnavailable, body: ``, want: LevelClean},
		{name: "invalid body", status: http.StatusOK, body: `not json`, want: LevelClean},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			if v := NewHTTPSource(server.URL, "test-key", server.Client()).Lookup(net.ParseIP("1.2.3.4")); v.Level != tc.want {
				t.Fatalf("level = %d, want %d", v.Level, tc.want)
			}
		})
	}
}

// Close est appelé à l'arrêt du WAF : un double appel, ou un miss concurrent
// (requête encore en vol), ne doivent pas paniquer sur la file fermée.
func TestCheckerCloseIsIdempotentAndSafeWithConcurrentMisses(t *testing.T) {
	checker := NewChecker(time.Hour, NewStaticSource())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 1000 {
			checker.Verdict(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
		}
	}()
	checker.Close()
	checker.Close()
	<-done

	if v := checker.Verdict("10.9.9.9"); v.Level != LevelClean {
		t.Fatalf("level after Close = %d, want clean", v.Level)
	}
}

// FR-24 : la réputation s'applique à un asset statique sans remplacer sa
// raison static_asset, qui en ferait un PASS de whitelist IP.
func TestMiddlewareKeepsStaticAssetReason(t *testing.T) {
	source := NewStaticSource().Add("5.5.5.0/24", LevelMalicious, "blocklist")
	checker := NewChecker(time.Hour, source)
	checker.resolveSync("5.5.5.5")
	scores, store := newScores(t)
	defer store.Close()
	scores.Set("5.5.5.5", "example.test", 80)

	request := httptest.NewRequest(http.MethodGet, "http://example.test/app.js", nil)
	request.RemoteAddr = "5.5.5.5:1234"
	request.Header.Set("X-WAF-Action", "PASS")
	request.Header.Set("X-WAF-Reason", "static_asset")
	NewMiddleware(checker, scores).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-WAF-Reason"); got != "static_asset" {
			t.Fatalf("X-WAF-Reason = %q, want static_asset", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), request)

	if got := scores.Get("5.5.5.5", "example.test").Score; got > ceilingMalicious {
		t.Fatalf("score = %d, want <= %d (the asset is evaluated)", got, ceilingMalicious)
	}
}

// unavailableSource ne se prononce jamais (API en panne, quota épuisé).
type unavailableSource struct{}

func (unavailableSource) Lookup(net.IP) Verdict { return unavailable }

// FR-13 : un verdict propre obtenu sur source indisponible n'est gardé qu'une
// minute ; il l'était cache_ttl (1 h), et un timeout blanchissait l'IP.
func TestCheckerCachesUnavailableVerdictBriefly(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	checker := NewChecker(time.Hour, unavailableSource{})
	defer checker.Close()
	checker.cache.WithClock(func() time.Time { return now })

	checker.resolveSync("1.2.3.4")
	if _, cached := checker.cache.Get("1.2.3.4"); !cached {
		t.Fatal("the unavailable verdict should be cached briefly")
	}
	now = now.Add(unavailableTTL)
	if _, cached := checker.cache.Get("1.2.3.4"); cached {
		t.Fatal("the unavailable verdict outlived unavailableTTL")
	}

	// Une source qui classe l'IP l'emporte : le verdict est gardé cache_ttl.
	classified := NewChecker(time.Hour, unavailableSource{}, NewStaticSource().Add("5.5.5.0/24", LevelMalicious, "blocklist"))
	defer classified.Close()
	if verdict := classified.resolveSync("5.5.5.5"); verdict.Level != LevelMalicious || verdict.Unavailable {
		t.Fatalf("verdict = %+v, want malicious and available", verdict)
	}
}

// FR-13 : un 429 suspend les appels jusqu'au Retry-After.
func TestHTTPSourcePausesOnQuotaExhaustion(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "3600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	source := NewHTTPSource(server.URL, "test-key", server.Client())
	source.now = func() time.Time { return now }

	if verdict := source.Lookup(net.ParseIP("1.2.3.4")); !verdict.Unavailable || verdict.Level != LevelClean {
		t.Fatalf("429 verdict = %+v, want clean and unavailable", verdict)
	}
	source.Lookup(net.ParseIP("1.2.3.5"))
	if got := calls.Load(); got != 1 {
		t.Fatalf("API calls during the pause = %d, want 1", got)
	}
	now = now.Add(time.Hour)
	source.Lookup(net.ParseIP("1.2.3.6"))
	if got := calls.Load(); got != 2 {
		t.Fatalf("API calls after Retry-After = %d, want 2", got)
	}
}
