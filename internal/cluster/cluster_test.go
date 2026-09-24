package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/middleware/access"
	"github.com/gaetandev/waf/internal/storage"
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

func newTestSyncer(t *testing.T, bus Bus) (*Syncer, *memory.Store, *access.RuleSet) {
	t.Helper()
	store := memory.New(100)
	t.Cleanup(store.Close)
	rules, err := access.NewRuleSet(nil, nil, nil)
	if err != nil {
		t.Fatalf("NewRuleSet() error = %v", err)
	}
	return NewSyncer(bus, store, rules), store, rules
}

// Régression : Syncer.Publish n'était appelé nulle part — aucun nœud ne
// diffusait ses blocages. Les événements publiés par un nœud atteignent les
// autres, et l'émetteur ignore l'écho que Pub/Sub lui renvoie.
func TestSyncerPropagatesBetweenNodesAndIgnoresOwnEcho(t *testing.T) {
	bus := NewLocalBus()
	origin, _, originRules := newTestSyncer(t, bus)
	peer, _, peerRules := newTestSyncer(t, bus)
	for _, syncer := range []*Syncer{origin, peer} {
		if err := syncer.Start(context.Background()); err != nil {
			t.Fatalf("Start() error = %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go origin.RunPublisher(ctx)

	origin.PublishBlacklistAdd("5.5.5.5")

	deadline := time.Now().Add(2 * time.Second)
	for peer.AppliedCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ok, _ := peerRules.IsBlacklisted("5.5.5.5"); !ok {
		t.Fatal("peer node must apply the blacklist entry published by the origin node")
	}
	if origin.AppliedCount() != 0 {
		t.Fatalf("origin applied %d events, want 0: its own echo must be ignored", origin.AppliedCount())
	}
	if ok, _ := originRules.IsBlacklisted("5.5.5.5"); ok {
		t.Fatal("the syncer must not re-apply the origin's own event")
	}
}

// FR-20 : « la durée du blocage est la même sur tous les nœuds ». Poser un
// score, comme auparavant, n'ouvrait pas le circuit.
func TestSyncerOpensPropagatedCircuitUntilSameDeadline(t *testing.T) {
	syncer, store, _ := newTestSyncer(t, NewLocalBus())
	until := time.Now().Add(4 * time.Minute).Truncate(time.Second)
	ipHash := trust.HashIP("6.6.6.6")

	syncer.Apply(Event{Type: EventCircuitOpen, Node: "other", IPHash: ipHash, Until: &until})

	visitor, ok := store.GetVisitor(ipHash)
	if !ok || !visitor.CircuitOpen || visitor.CircuitOpenUntil == nil || !visitor.CircuitOpenUntil.Equal(until) {
		t.Fatalf("visitor = %+v ok=%v, want circuit open until %s", visitor, ok, until)
	}
}

func TestSyncerCriticalScoreNeverRaisesLocalScore(t *testing.T) {
	syncer, store, _ := newTestSyncer(t, NewLocalBus())
	ipHash := trust.HashIP("7.7.7.7")
	now := time.Now()
	store.SetVisitor(ipHash, storage.VisitorState{IPHash: ipHash, Score: 2, ReqCount: 42, ExpiresAt: now.Add(time.Hour)})

	syncer.Apply(Event{Type: EventScoreCritical, Node: "other", IPHash: ipHash, Score: 4})

	visitor, _ := store.GetVisitor(ipHash)
	if visitor.Score != 2 || visitor.ReqCount != 42 {
		t.Fatalf("visitor = %+v, want score 2 and local state kept", visitor)
	}
}

func TestSyncerEnqueueNeverBlocks(t *testing.T) {
	syncer, _, _ := newTestSyncer(t, NewLocalBus())
	for range outboxSize + 10 { // aucun publicateur : la file se remplit
		syncer.PublishBlacklistAdd("1.1.1.1")
	}
}

func TestSyncerRoutesPropagatedBlacklistThroughTheApplier(t *testing.T) {
	rules, err := access.NewRuleSet(nil, nil, nil)
	if err != nil {
		t.Fatalf("NewRuleSet() error = %v", err)
	}
	syncer := NewSyncer(NewLocalBus(), nil, rules)
	var applied []string
	syncer.WithBlacklistApplier(func(value string) error {
		applied = append(applied, value)
		return nil
	})

	syncer.Apply(Event{Type: EventBlacklistAdd, Value: "9.9.9.9"})

	if len(applied) != 1 || applied[0] != "9.9.9.9" {
		t.Fatalf("applied = %v, want [9.9.9.9]", applied)
	}
	if ok, _ := rules.IsBlacklisted("9.9.9.9"); ok {
		t.Fatal("entry written behind the applier's back, want the applier as sole writer")
	}
}
