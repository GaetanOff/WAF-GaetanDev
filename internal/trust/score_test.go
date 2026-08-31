package trust

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
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
