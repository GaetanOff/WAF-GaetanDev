package alert

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := NewNotifier([]Sink{{Type: SinkGeneric, URL: server.URL}}, time.Hour, 0, server.Client())
	defer n.Close()
	for range 5 {
		n.Notify(Event{Trigger: "block", Domain: "example.com", Reason: "blocked"})
	}
	time.Sleep(100 * time.Millisecond)

	if c := count.Load(); c != 1 {
		t.Fatalf("delivered %d times, want 1 (cooldown dedup)", c)
	}
}

// Une transition de mode (Immediate) doit toujours être livrée, même si une
// transition identique a eu lieu dans le cooldown : sinon une réactivation
// rapprochée du mode sous attaque (FR-39) passerait silencieuse.
func TestImmediateBypassesCooldown(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := NewNotifier([]Sink{{Type: SinkGeneric, URL: server.URL}}, time.Hour, 0, server.Client())
	defer n.Close()
	for range 3 {
		n.Notify(Event{Trigger: "under_attack_start", Domain: "status.gaetandev.fr", Immediate: true})
	}
	time.Sleep(100 * time.Millisecond)

	if c := count.Load(); c != 3 {
		t.Fatalf("delivered %d times, want 3 (les transitions Immediate ignorent le cooldown)", c)
	}
}

func TestRetryOnFailureThenSuccess(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) < 2 {
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

	if a := attempts.Load(); a < 2 {
		t.Fatalf("attempts = %d, want >= 2 (retry)", a)
	}
}

// Le cooldown dédoublonne par trigger+domaine, et sa mémoire est bornée : le
// domaine est le Host de la requête, qu'un client fait varier à volonté.
func TestCooldownDeduplicatesAndStaysBounded(t *testing.T) {
	n := NewNotifier(nil, time.Minute, 0, nil)
	defer n.Close()
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	n.now = func() time.Time { return clock }

	if !n.allow(Alert{Trigger: "block", Domain: "example.com"}) {
		t.Fatal("first alert must be allowed")
	}
	if n.allow(Alert{Trigger: "block", Domain: "example.com"}) {
		t.Fatal("second alert within the cooldown must be suppressed")
	}
	clock = clock.Add(time.Minute)
	if !n.allow(Alert{Trigger: "block", Domain: "example.com"}) {
		t.Fatal("alert after the cooldown must be allowed")
	}

	for i := range maxCooldownKeys * 2 {
		n.allow(Alert{Trigger: "block", Domain: "random-" + strconv.Itoa(i) + ".test"})
	}
	if got := n.lastSent.Len(); got > maxCooldownKeys {
		t.Fatalf("cooldown entries = %d, want at most %d", got, maxCooldownKeys)
	}
}

// recordingObserver consigne l'issue des livraisons ; outcomes est fermé à la
// première issue attendue pour éviter les attentes à durée fixe.
type recordingObserver struct {
	mu      sync.Mutex
	sent    []string
	failed  []string
	outcome chan struct{}
}

func newRecordingObserver() *recordingObserver {
	return &recordingObserver{outcome: make(chan struct{}, 16)}
}

func (o *recordingObserver) AlertSent(trigger string) {
	o.mu.Lock()
	o.sent = append(o.sent, trigger)
	o.mu.Unlock()
	o.outcome <- struct{}{}
}

func (o *recordingObserver) AlertFailed(trigger string) {
	o.mu.Lock()
	o.failed = append(o.failed, trigger)
	o.mu.Unlock()
	o.outcome <- struct{}{}
}

func (o *recordingObserver) wait(t *testing.T, outcomes int) {
	t.Helper()
	for range outcomes {
		select {
		case <-o.outcome:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for a delivery outcome")
		}
	}
}

// FR-29 : chaque livraison à un sink alimente waf_alerts_sent_total ou
// waf_alerts_failed_total.
func TestNotifierReportsDeliveryOutcomes(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthy.Close()
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failing.Close()
	observer := newRecordingObserver()

	n := NewNotifier([]Sink{{Type: SinkGeneric, URL: healthy.URL}, {Type: SinkGeneric, URL: failing.URL}}, time.Minute, 0, healthy.Client(), WithObserver(observer))
	defer n.Close()
	n.Notify(Event{Trigger: TriggerHoneypot, Domain: "example.com"})
	observer.wait(t, 2)

	observer.mu.Lock()
	defer observer.mu.Unlock()
	if len(observer.sent) != 1 || observer.sent[0] != TriggerHoneypot {
		t.Fatalf("sent = %v, want [honeypot]", observer.sent)
	}
	if len(observer.failed) != 1 || observer.failed[0] != TriggerHoneypot {
		t.Fatalf("failed = %v, want [honeypot]", observer.failed)
	}
}
