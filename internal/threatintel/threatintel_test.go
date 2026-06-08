package threatintel

import (
	"net"
	"net/http"
	"net/http/httptest"
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
