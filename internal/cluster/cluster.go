// Package cluster propage en temps réel les décisions critiques entre nœuds WAF
// (FR-20) via un bus Pub/Sub. Le modèle est en cohérence éventuelle ; si le bus
// (Redis) est indisponible, chaque nœud continue de fonctionner de manière
// autonome (dégradé mais opérationnel).
package cluster

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/gaetandev/waf/internal/middleware/access"
	"github.com/gaetandev/waf/internal/storage"
)

// Types d'événements propagés (FR-20).
const (
	EventBlacklistAdd  = "blacklist_add"
	EventScoreCritical = "score_critical"
	EventCircuitOpen   = "circuit_open"
	EventDegradedMode  = "degraded_mode"
)

// Event est un message de synchronisation inter-nœuds.
type Event struct {
	Type   string `json:"type"`
	Value  string `json:"value,omitempty"`   // IP/CIDR pour blacklist_add
	IPHash string `json:"ip_hash,omitempty"` // pour score_critical/circuit_open
	Domain string `json:"domain,omitempty"`
	Score  int    `json:"score,omitempty"`
}

// Bus abstrait le transport Pub/Sub (Redis en production, local en mono-nœud
// et en test).
type Bus interface {
	Publish(ctx context.Context, event Event) error
	Subscribe(ctx context.Context, handler func(Event)) error
	Close() error
}

// Syncer applique les événements entrants à l'état local et publie les
// événements locaux.
type Syncer struct {
	bus   Bus
	store storage.Store
	rules *access.RuleSet
	now   func() time.Time

	mu      sync.Mutex
	applied int
}

func NewSyncer(bus Bus, store storage.Store, rules *access.RuleSet) *Syncer {
	return &Syncer{bus: bus, store: store, rules: rules, now: time.Now}
}

// Start s'abonne au bus et applique chaque événement entrant.
func (s *Syncer) Start(ctx context.Context) error {
	return s.bus.Subscribe(ctx, s.Apply)
}

// Apply mute l'état local selon l'événement reçu. Idempotent.
func (s *Syncer) Apply(event Event) {
	switch event.Type {
	case EventBlacklistAdd:
		if s.rules != nil && event.Value != "" {
			_ = s.rules.AddBlacklist(event.Value)
		}
	case EventScoreCritical, EventCircuitOpen:
		if s.store != nil && event.IPHash != "" {
			now := s.now()
			s.store.SetVisitor(event.IPHash, storage.VisitorState{
				IPHash:    event.IPHash,
				Domain:    event.Domain,
				Score:     event.Score,
				FirstSeen: now,
				LastSeen:  now,
				ExpiresAt: now.Add(time.Hour),
			})
		}
	}
	s.mu.Lock()
	s.applied++
	s.mu.Unlock()
}

// AppliedCount retourne le nombre d'événements appliqués (observabilité/tests).
func (s *Syncer) AppliedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applied
}

// Publish émet un événement local vers les autres nœuds (best-effort : une
// erreur de bus n'interrompt pas le traitement local, fallback autonome).
func (s *Syncer) Publish(ctx context.Context, event Event) {
	_ = s.bus.Publish(ctx, event)
}

// LocalBus est un bus en mémoire (mono-nœud / tests). Les publications sont
// délivrées aux abonnés du même process.
type LocalBus struct {
	mu       sync.Mutex
	handlers []func(Event)
}

func NewLocalBus() *LocalBus { return &LocalBus{} }

func (b *LocalBus) Publish(_ context.Context, event Event) error {
	b.mu.Lock()
	handlers := append([]func(Event){}, b.handlers...)
	b.mu.Unlock()
	for _, h := range handlers {
		h(event)
	}
	return nil
}

func (b *LocalBus) Subscribe(_ context.Context, handler func(Event)) error {
	b.mu.Lock()
	b.handlers = append(b.handlers, handler)
	b.mu.Unlock()
	return nil
}

func (b *LocalBus) Close() error { return nil }

// encode/decode exposés pour le transport Redis.
func encode(event Event) ([]byte, error) { return json.Marshal(event) }

func decode(data []byte) (Event, error) {
	var event Event
	err := json.Unmarshal(data, &event)
	return event, err
}
