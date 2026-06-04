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
	manager, store := newTestManager(t)
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
	manager, store := newTestManager(t)
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
	manager, store := newTestManager(t)
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
	manager, store := newTestManager(t)
	defer store.Close()

	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	manager.Set("8.8.8.8", "example.test", 90)

	now = now.Add(65 * time.Minute)
	visitor := manager.Get("8.8.8.8", "example.test")

	if visitor.Score != 50 {
		t.Fatalf("Score = %d, want reset initial score 50", visitor.Score)
	}
}

func TestTrustMiddlewareBlocksBelowThreshold(t *testing.T) {
	manager, store := newTestManager(t)
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
	manager, store := newTestManager(t)
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

func newTestManager(t *testing.T) (*ScoreManager, *memory.Store) {
	t.Helper()

	store := memory.New(100)
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
	return manager, store
}
