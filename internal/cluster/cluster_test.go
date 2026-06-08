package cluster

import (
	"context"
	"testing"

	"github.com/gaetandev/waf/internal/middleware/access"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/trust"
)

func TestLocalBusRoundTrip(t *testing.T) {
	bus := NewLocalBus()
	var received Event
	_ = bus.Subscribe(context.Background(), func(e Event) { received = e })
	_ = bus.Publish(context.Background(), Event{Type: EventBlacklistAdd, Value: "1.2.3.4"})

	if received.Type != EventBlacklistAdd || received.Value != "1.2.3.4" {
		t.Fatalf("received = %+v, want blacklist_add 1.2.3.4", received)
	}
}

func TestSyncerAppliesBlacklistAndScore(t *testing.T) {
	store := memory.New(100)
	defer store.Close()
	rules, err := access.NewRuleSet(nil, nil, nil)
	if err != nil {
		t.Fatalf("NewRuleSet() error = %v", err)
	}
	bus := NewLocalBus()
	syncer := NewSyncer(bus, store, rules)
	if err := syncer.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// blacklist_add propagé → l'IP devient blacklistée localement.
	_ = bus.Publish(context.Background(), Event{Type: EventBlacklistAdd, Value: "9.9.9.9"})
	if ok, _ := rules.IsBlacklisted("9.9.9.9"); !ok {
		t.Fatal("propagated blacklist entry must be applied locally")
	}

	// score_critical propagé → le visiteur est stocké avec un score bas.
	ipHash := trust.HashIP("5.5.5.5")
	_ = bus.Publish(context.Background(), Event{Type: EventScoreCritical, IPHash: ipHash, Domain: "example.test", Score: 0})
	visitor, ok := store.GetVisitor(ipHash)
	if !ok || visitor.Score != 0 {
		t.Fatalf("propagated critical score not applied: ok=%v visitor=%+v", ok, visitor)
	}

	if syncer.AppliedCount() != 2 {
		t.Fatalf("applied = %d, want 2", syncer.AppliedCount())
	}
}
