package alert

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNotifierDeliversToWebhook(t *testing.T) {
	var got map[string]string
	var wg sync.WaitGroup
	wg.Add(1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
		wg.Done()
	}))
	defer server.Close()

	n := NewNotifier([]Sink{{Type: SinkSlack, URL: server.URL}}, time.Minute, 0, server.Client())
	defer n.Close()
	n.Notify("circuit_breaker", "example.com", "circuit open")

	wg.Wait()
	if got["text"] == "" {
		t.Fatalf("slack payload missing text: %v", got)
	}
}

func TestCooldownDeduplicates(t *testing.T) {
	var count int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&count, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := NewNotifier([]Sink{{Type: SinkGeneric, URL: server.URL}}, time.Hour, 0, server.Client())
	defer n.Close()
	for i := 0; i < 5; i++ {
		n.Notify("block", "example.com", "blocked")
	}
	time.Sleep(100 * time.Millisecond)

	if c := atomic.LoadInt32(&count); c != 1 {
		t.Fatalf("delivered %d times, want 1 (cooldown dedup)", c)
	}
}

func TestRetryOnFailureThenSuccess(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&attempts, 1) < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := NewNotifier([]Sink{{Type: SinkGeneric, URL: server.URL}}, time.Minute, 3, server.Client())
	defer n.Close()
	n.Notify("block", "example.com", "blocked")
	time.Sleep(500 * time.Millisecond)

	if a := atomic.LoadInt32(&attempts); a < 2 {
		t.Fatalf("attempts = %d, want >= 2 (retry)", a)
	}
}
