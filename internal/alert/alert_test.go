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
	var got slackPayload
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
	n.Notify(Event{Trigger: "circuit_breaker", Domain: "example.com", Reason: "circuit open"})

	wg.Wait()
	if len(got.Attachments) != 1 {
		t.Fatalf("slack payload missing attachment: %+v", got)
	}
	if got.Attachments[0].Title == "" {
		t.Fatal("slack attachment missing title")
	}
}

func TestDiscordEmbedIsRich(t *testing.T) {
	payload := encode(SinkDiscord, Alert{
		Timestamp: "2026-06-11T12:00:00Z",
		Trigger:   "honeypot",
		Severity:  "critical",
		Domain:    "api.gaetandev.fr",
		Title:     titleFor("honeypot"),
		Message:   "msg",
		Reason:    "honeypot_path",
		IP:        "1.2.3.0",
		Path:      "/.env",
		Method:    "GET",
		Action:    "HONEYPOT",
		RequestID: "abc-123",
		Country:   "FR",
	})
	var got discordPayload
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("discord payload invalid JSON: %v", err)
	}
	if len(got.Embeds) != 1 {
		t.Fatalf("expected 1 embed, got %d", len(got.Embeds))
	}
	embed := got.Embeds[0]
	if embed.Color != 0xE74C3C {
		t.Fatalf("color = %d, want red for critical", embed.Color)
	}
	if embed.Timestamp != "2026-06-11T12:00:00Z" {
		t.Fatalf("embed timestamp not propagated: %q", embed.Timestamp)
	}
	// Les champs clés doivent être présents.
	names := map[string]string{}
	for _, f := range embed.Fields {
		names[f.Name] = f.Value
	}
	for _, want := range []string{"Domaine", "IP", "Chemin", "Raison", "Pays"} {
		if _, ok := names[want]; !ok {
			t.Fatalf("embed missing field %q (got %v)", want, names)
		}
	}
	if names["IP"] != "1.2.3.0" {
		t.Fatalf("IP field = %q, want 1.2.3.0", names["IP"])
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
		n.Notify(Event{Trigger: "block", Domain: "example.com", Reason: "blocked"})
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
	n.Notify(Event{Trigger: "block", Domain: "example.com", Reason: "blocked"})
	time.Sleep(500 * time.Millisecond)

	if a := atomic.LoadInt32(&attempts); a < 2 {
		t.Fatalf("attempts = %d, want >= 2 (retry)", a)
	}
}
