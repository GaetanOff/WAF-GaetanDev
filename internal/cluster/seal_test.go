package cluster

import (
	"strings"
	"testing"
	"time"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func TestSealedEventRoundTrips(t *testing.T) {
	key := EventKey(testSecret)
	until := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	sent := Event{Type: EventCircuitOpen, Node: "0123456789abcdef", TS: until, IPHash: "fedcba9876543210", Until: &until}
	message, err := seal(key, sent)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	received, err := open(key, string(message), until)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if received.Type != sent.Type || received.IPHash != sent.IPHash || !received.Until.Equal(until) {
		t.Fatalf("received %+v, want %+v", received, sent)
	}
}

// multi-node-sync.feature, « Événement non signé ou mal signé — ignoré ».
func TestOpenRejectsUnsignedAndForgedMessages(t *testing.T) {
	key := EventKey(testSecret)
	genuine, err := seal(key, Event{Type: EventBlacklistAdd, Value: "5.5.5.5"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	signature, _, _ := strings.Cut(string(genuine), ".")
	otherKey, err := seal(EventKey("another-secret-another-secret-00"), Event{Type: EventBlacklistAdd, Value: "0.0.0.0/0"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	tests := map[string]string{
		"legacy unsigned JSON":      `{"type":"blacklist_add","value":"0.0.0.0/0"}`,
		"empty signature":           `.{"type":"blacklist_add","value":"0.0.0.0/0"}`,
		"signature of another body": signature + `.{"type":"blacklist_add","value":"0.0.0.0/0"}`,
		"signed by another secret":  string(otherKey),
		"garbage signature":         `!!!.{"type":"blacklist_add","value":"0.0.0.0/0"}`,
	}
	for name, message := range tests {
		t.Run(name, func(t *testing.T) {
			if event, err := open(key, message, time.Now()); err == nil {
				t.Fatalf("open accepted %q as %+v", message, event)
			}
		})
	}
}

// multi-node-sync.feature, « Événement de type inconnu — ignoré ».
func TestOpenRejectsUnknownEventTypes(t *testing.T) {
	key := EventKey(testSecret)
	for _, eventType := range []string{"reboot", "degraded_mode", ""} {
		message, err := seal(key, Event{Type: eventType})
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		if _, err := open(key, string(message), time.Now()); err == nil {
			t.Fatalf("open accepted the unknown type %q", eventType)
		}
	}
}

// multi-node-sync.feature, « Événement rejoué hors fenêtre — ignoré » : un
// message signé mais capturé se rejouait indéfiniment.
func TestOpenRejectsStaleOrUndatedEvents(t *testing.T) {
	key := EventKey(testSecret)
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for name, ts := range map[string]time.Time{
		"undated":           {},
		"captured 10m ago":  now.Add(-10 * time.Minute),
		"10m in the future": now.Add(10 * time.Minute),
	} {
		message, err := seal(key, Event{Type: EventBlacklistAdd, TS: ts, Value: "5.5.5.5"})
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		if _, err := open(key, string(message), now); err == nil {
			t.Fatalf("%s: open accepted the event", name)
		}
	}
	fresh, err := seal(key, Event{Type: EventBlacklistAdd, TS: now.Add(-time.Minute), Value: "5.5.5.5"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := open(key, string(fresh), now); err != nil {
		t.Fatalf("open refused an event within the window: %v", err)
	}
}

func TestSealAndOpenRefuseAnEmptyKey(t *testing.T) {
	if _, err := seal(nil, Event{Type: EventBlacklistAdd, Value: "5.5.5.5"}); err == nil {
		t.Fatal("seal signed with an empty key")
	}
	if _, err := open(nil, "x."+`{"type":"blacklist_add","value":"5.5.5.5"}`, time.Now()); err == nil {
		t.Fatal("open accepted a message with an empty key")
	}
}

func TestRedisBusCountsRejectedMessagesAndNeverDeliversThem(t *testing.T) {
	bus := &RedisBus{key: EventKey(testSecret)}
	var delivered []Event
	handler := func(event Event) { delivered = append(delivered, event) }

	bus.deliver(`{"type":"blacklist_add","value":"0.0.0.0/0"}`, handler)
	genuine, err := seal(bus.key, Event{Type: EventBlacklistAdd, TS: time.Now(), Value: "5.5.5.5"})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	bus.deliver(string(genuine), handler)

	if bus.Rejected() != 1 {
		t.Fatalf("rejected = %d, want 1", bus.Rejected())
	}
	if len(delivered) != 1 || delivered[0].Value != "5.5.5.5" {
		t.Fatalf("delivered %+v, want only the signed event", delivered)
	}
}

func TestSyncerIgnoresUnknownEventTypes(t *testing.T) {
	syncer := NewSyncer(NewLocalBus(), nil, nil)
	if syncer.Apply(Event{Type: "reboot", Node: "0000000000000000"}) {
		t.Fatal("Apply reported an unknown event type as applied")
	}
	if syncer.AppliedCount() != 0 {
		t.Fatalf("applied = %d, want 0", syncer.AppliedCount())
	}
}
