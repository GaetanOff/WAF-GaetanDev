package selfprotect

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWindowRecordAndLimited(t *testing.T) {
	w := NewWindow(3, time.Minute)
	for i := 1; i <= 3; i++ {
		w.Record("1.2.3.4")
	}
	if !w.Limited("1.2.3.4") {
		t.Fatal("expected IP to be limited after reaching max")
	}
	if w.Limited("5.6.7.8") {
		t.Fatal("other IP must not be limited")
	}
}

func TestWindowResetsAfterExpiry(t *testing.T) {
	w := NewWindow(2, time.Minute)
	now := time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return now }
	w.Record("1.2.3.4")
	w.Record("1.2.3.4")
	if !w.Limited("1.2.3.4") {
		t.Fatal("should be limited")
	}
	now = now.Add(2 * time.Minute) // fenêtre écoulée
	if w.Limited("1.2.3.4") {
		t.Fatal("window should have reset")
	}
}

func TestPathGuardLimitsTargetPath(t *testing.T) {
	window := NewWindow(2, time.Minute)
	guard := PathGuard("/waf/verify", window)
	handler := guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	statuses := make([]int, 0, 3)
	for range 3 {
		req := httptest.NewRequest(http.MethodPost, "http://x/waf/verify", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		statuses = append(statuses, rr.Code)
	}
	if statuses[0] != http.StatusNoContent || statuses[1] != http.StatusNoContent {
		t.Fatalf("first two requests should pass: %v", statuses)
	}
	if statuses[2] != http.StatusTooManyRequests {
		t.Fatalf("third request should be 429, got %d", statuses[2])
	}
}

func TestPathGuardIgnoresOtherPaths(t *testing.T) {
	window := NewWindow(1, time.Minute)
	guard := PathGuard("/waf/verify", window)
	handler := guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for range 5 {
		req := httptest.NewRequest(http.MethodGet, "http://x/other", nil)
		req.RemoteAddr = "1.2.3.4:1234"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("non-target path must not be limited, got %d", rr.Code)
		}
	}
}
