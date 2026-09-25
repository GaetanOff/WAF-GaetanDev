package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/storage"
	"github.com/gaetandev/waf/internal/storage/memory"
)

func TestScoreManagerInitializesNewVisitor(t *testing.T) {
	manager, store, _ := newTestManager(t)
	defer store.Close()

	visitor := manager.Get("4.4.4.4", "example.test")

	if visitor.Score != 50 {
		t.Fatalf("Score = %d, want 50", visitor.Score)
	}
	if state := manager.State(visitor.Score); state != StateMonitored {
		t.Fatalf("state = %s, want MONITORED", state)
	}
}

func TestScoreManagerApplyDeltaAndClamp(t *testing.T) {
	manager, store, _ := newTestManager(t)
	defer store.Close()

	manager.Set("1.2.3.4", "example.test", 35)
	visitor := manager.Apply("1.2.3.4", "example.test", DeltaChallengePassed)

	if visitor.Score != 60 {
		t.Fatalf("Score = %d, want 60", visitor.Score)
	}
	visitor = manager.Apply("1.2.3.4", "example.test", 200)
	if visitor.Score != 100 {
		t.Fatalf("Score = %d, want clamp 100", visitor.Score)
	}
}

func TestScoreManagerStateTransitions(t *testing.T) {
	manager, store, _ := newTestManager(t)
	defer store.Close()

	tests := []struct {
		score int
		want  string
	}{
		{score: 75, want: StateTrusted},
		{score: 45, want: StateMonitored},
		{score: 35, want: StateChallenged},
		{score: 10, want: StateBlocked},
		{score: 0, want: StateBlocked},
	}

	for _, tt := range tests {
		if got := manager.State(tt.score); got != tt.want {
			t.Fatalf("State(%d) = %s, want %s", tt.score, got, tt.want)
		}
	}
}

func TestScoreManagerResetsExpiredVisitor(t *testing.T) {
	manager, store, clock := newTestManager(t)
	defer store.Close()

	clock.set(time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC))
	manager.Set("8.8.8.8", "example.test", 90)

	clock.advance(65 * time.Minute) // au-delà du score_ttl (1h) : l'entrée expire
	visitor := manager.Get("8.8.8.8", "example.test")

	if visitor.Score != 50 {
		t.Fatalf("Score = %d, want reset initial score 50", visitor.Score)
	}
}

func TestPenalizeRateLimitOncePerWindow(t *testing.T) {
	manager, store, clock := newTestManager(t)
	defer store.Close()

	clock.set(time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC))
	manager.Set("1.2.3.4", "example.test", 50)

	if visitor := manager.PenalizeRateLimit("1.2.3.4", "example.test"); visitor.Score != 40 {
		t.Fatalf("Score after first penalty = %d, want 40", visitor.Score)
	}
	// Refus supplémentaires dans la même fenêtre : aucune pénalité de plus.
	for range 15 {
		if visitor := manager.PenalizeRateLimit("1.2.3.4", "example.test"); visitor.Score != 40 {
			t.Fatalf("Score within window = %d, want 40 (single penalty per window)", visitor.Score)
		}
	}

	clock.advance(RateLimitPenaltyWindow)
	if visitor := manager.PenalizeRateLimit("1.2.3.4", "example.test"); visitor.Score != 30 {
		t.Fatalf("Score in next window = %d, want 30", visitor.Score)
	}
}

func TestTrustMiddlewareBlocksBelowThreshold(t *testing.T) {
	manager, store, _ := newTestManager(t)
	defer store.Close()
	manager.Set("9.9.9.9", "example.test", 2)

	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "9.9.9.9:1234"
	response := httptest.NewRecorder()

	manager.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not be called")
	})).ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestTrustMiddlewareMarksChallengeState(t *testing.T) {
	manager, store, _ := newTestManager(t)
	defer store.Close()
	manager.Set("9.9.9.9", "example.test", 25)

	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "9.9.9.9:1234"
	response := httptest.NewRecorder()

	var action string
	manager.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action = r.Header.Get("X-WAF-Action")
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
	if action != "CHALLENGE" {
		t.Fatalf("X-WAF-Action = %q, want CHALLENGE", action)
	}
}

// tls-fingerprinting.feature / threat-intelligence.feature : sans moteur de
// risque, le middleware de score applique lui-même les déclencheurs
// déterministes publiés par les détecteurs, quel que soit le score.
func TestTrustMiddlewareBlocksOnDeterministicTrigger(t *testing.T) {
	cases := []struct {
		trigger    string
		reason     string
		wantReason string
	}{
		{trigger: "ja3_blacklist", reason: "ja3_blacklisted", wantReason: "ja3_blacklisted"},
		{trigger: "threat_intel_critical", reason: "abuseipdb_critical", wantReason: "abuseipdb_critical"},
		{trigger: "threat_intel_critical", wantReason: "deterministic_threat_intel_critical"},
	}
	for _, tc := range cases {
		t.Run(tc.trigger+"/"+tc.wantReason, func(t *testing.T) {
			manager, store, _ := newTestManager(t)
			defer store.Close()
			manager.Set("9.9.9.9", "example.test", 100)

			request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
			request.RemoteAddr = "9.9.9.9:1234"
			request.Header.Set("X-WAF-Deterministic-Trigger", tc.trigger)
			if tc.reason != "" {
				request.Header.Set("X-WAF-Reason", tc.reason)
			}
			response := httptest.NewRecorder()

			manager.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("a deterministic trigger must not reach the upstream")
			})).ServeHTTP(response, request)

			if response.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", response.Code)
			}
			if got := response.Header().Get("X-WAF-Action"); got != "BLOCK" {
				t.Fatalf("X-WAF-Action = %q, want BLOCK", got)
			}
			if got := response.Header().Get("X-WAF-Reason"); got != tc.wantReason {
				t.Fatalf("X-WAF-Reason = %q, want %q", got, tc.wantReason)
			}
			if got := response.Header().Get("X-WAF-Deterministic-Trigger"); got != tc.trigger {
				t.Fatalf("X-WAF-Deterministic-Trigger = %q, want %q", got, tc.trigger)
			}
		})
	}
}

// Seules les valeurs de l'énumération FR-35 bloquent : un en-tête inconnu est
// ignoré (l'ingress supprime de toute façon les X-WAF-* fournis par le client).
func TestTrustMiddlewareIgnoresUnknownTrigger(t *testing.T) {
	manager, store, _ := newTestManager(t)
	defer store.Close()

	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "9.9.9.9:1234"
	request.Header.Set("X-WAF-Deterministic-Trigger", "unknown")
	response := httptest.NewRecorder()

	manager.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}

// fakeClock est une horloge mutable partagée par le ScoreManager et le Store en
// test. Le stamping du TTL (ExpiresAt) et l'éviction du Store lisent ainsi le
// MÊME temps : câbler le Store sur time.Now pendant que le manager tourne sur une
// horloge injectée laissait le Store évincer des visiteurs que le manager croyait
// encore vivants — un date-bomb où un test figé dans le passé cassait au fil du
// temps réel.
type fakeClock struct{ current time.Time }

func (c *fakeClock) now() time.Time          { return c.current }
func (c *fakeClock) set(t time.Time)         { c.current = t }
func (c *fakeClock) advance(d time.Duration) { c.current = c.current.Add(d) }

func newTestManager(t *testing.T) (*ScoreManager, *memory.Store, *fakeClock) {
	t.Helper()

	clock := &fakeClock{current: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	store := memory.New(100, memory.WithClock(clock.now))
	cfg := config.Default()
	cfg.Version = "1.0"
	cfg.Server.Listen = ":0"
	cfg.Upstream.Address = "http://example.test"
	cfg.Challenge.Enabled = false
	cfg.Admin.Enabled = false

	manager, err := NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("NewScoreManager() error = %v", err)
	}
	manager.now = clock.now // horloge partagée : éviction et scoring d'accord
	return manager, store, clock
}

// FR-20 : un score qui passe sous CriticalScore est signalé une fois, pour
// être partagé avec les autres nœuds.
func TestScoreManagerNotifiesCriticalCrossingOnce(t *testing.T) {
	manager, store, _ := newTestManager(t)
	defer store.Close()
	var notified []int
	manager.WithCriticalObserver(func(visitor storage.VisitorState) { notified = append(notified, visitor.Score) })

	manager.Set("1.2.3.4", "example.test", 20)
	manager.Apply("1.2.3.4", "example.test", -10) // 10 : pas encore critique
	manager.Apply("1.2.3.4", "example.test", -8)  // 2 : franchissement
	manager.Apply("1.2.3.4", "example.test", -1)  // 1 : déjà critique

	if len(notified) != 1 || notified[0] != 2 {
		t.Fatalf("critical notifications = %v, want [2]", notified)
	}
}

func TestScoreManagerSetThresholdsAppliesAtRuntime(t *testing.T) {
	manager, store, _ := newTestManager(t)
	defer store.Close()
	if state := manager.State(35); state != StateChallenged {
		t.Fatalf("state(35) = %s, want CHALLENGED with the default thresholds", state)
	}
	manager.SetThresholds(30, 20)
	if state := manager.State(35); state != StateMonitored {
		t.Fatalf("state(35) = %s, want MONITORED after lowering the challenge threshold", state)
	}
	if state := manager.State(20); state != StateBlocked {
		t.Fatalf("state(20) = %s, want BLOCKED with block_threshold = 20", state)
	}
}

// countingStore compte les écritures de visiteurs : chacune est un SET Redis
// synchrone (ou le verrou global du store mémoire) sur le chemin de requête.
type countingStore struct {
	storage.Store
	writes int
}

func (s *countingStore) SetVisitor(key string, visitor storage.VisitorState) {
	s.writes++
	s.Store.SetVisitor(key, visitor)
}

func TestGetRewritesAKnownVisitorOncePerTouchInterval(t *testing.T) {
	manager, store, clock := newTestManager(t)
	defer store.Close()
	counting := &countingStore{Store: store}
	manager.store = counting
	manager.Set("1.2.3.4", "example.test", 60)
	counting.writes = 0

	for range 10 {
		manager.Get("1.2.3.4", "example.test")
	}
	if counting.writes != 0 {
		t.Fatalf("writes within the touch interval = %d, want 0", counting.writes)
	}

	clock.advance(maxTouchInterval)
	visitor := manager.Get("1.2.3.4", "example.test")

	if counting.writes != 1 {
		t.Fatalf("writes after the touch interval = %d, want 1", counting.writes)
	}
	if want := clock.now().Add(time.Hour); !visitor.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want the TTL slid to %v", visitor.ExpiresAt, want)
	}
}

func TestPeekNeverWrites(t *testing.T) {
	manager, store, clock := newTestManager(t)
	defer store.Close()
	counting := &countingStore{Store: store}
	manager.store = counting

	unknown := manager.Peek("5.5.5.5", "example.test")
	if unknown.Score != 50 {
		t.Fatalf("unknown visitor score = %d, want the initial score 50", unknown.Score)
	}
	if _, ok := store.GetVisitor(HashIP("5.5.5.5")); ok {
		t.Fatal("Peek created the visitor, want a read-only lookup")
	}

	manager.Set("1.2.3.4", "example.test", 20)
	counting.writes = 0
	clock.advance(maxTouchInterval)
	if known := manager.Peek("1.2.3.4", "example.test"); known.Score != 20 {
		t.Fatalf("known visitor score = %d, want 20", known.Score)
	}
	if counting.writes != 0 {
		t.Fatalf("Peek wrote %d times, want 0", counting.writes)
	}

	clock.advance(2 * time.Hour) // au-delà du score_ttl
	if expired := manager.Peek("1.2.3.4", "example.test"); expired.Score != 50 {
		t.Fatalf("expired visitor score = %d, want the initial score 50", expired.Score)
	}
}

// La clé est persistée (Redis, cookie de clearance, token de challenge) : son
// format ne doit pas changer d'une version à l'autre.
func TestHashIPIsStable(t *testing.T) {
	for ip, want := range map[string]string{
		"203.0.113.7": "fec52565aa0cf18f",
		"2001:db8::1": "5afd19e856d1c18d",
	} {
		if got := HashIP(ip); got != want {
			t.Fatalf("HashIP(%q) = %q, want %q", ip, got, want)
		}
	}
}

// Appels répétés pour la même IP, comme au fil d'une requête.
func BenchmarkHashIP(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		HashIP("2001:db8::1234:5678")
	}
}

// Une IP différente à chaque appel : le cache ne sert jamais.
func BenchmarkHashIPMiss(b *testing.B) {
	ips := make([]string, hashCacheSlots*4)
	for i := range ips {
		ips[i] = "10." + strconv.Itoa(i>>16&255) + "." + strconv.Itoa(i>>8&255) + "." + strconv.Itoa(i&255)
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		HashIP(ips[i%len(ips)])
		i++
	}
}

// Le cache ne rend jamais le hash d'une autre IP, y compris quand plusieurs
// IP se disputent les emplacements en parallèle.
func TestHashIPCacheNeverReturnsAnotherIPHash(t *testing.T) {
	ips := make([]string, hashCacheSlots*2)
	for i := range ips {
		ips[i] = "192.0." + strconv.Itoa(i>>8&255) + "." + strconv.Itoa(i&255) + ":" + strconv.Itoa(i)
	}
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for round := range 4 {
				for i := worker + round; i < len(ips); i += 8 {
					sum := sha256.Sum256([]byte(ips[i]))
					if got, want := HashIP(ips[i]), hex.EncodeToString(sum[:ipHashBytes]); got != want {
						t.Errorf("HashIP(%q) = %q, want %q", ips[i], got, want)
						return
					}
				}
			}
		})
	}
	wg.Wait()
}
