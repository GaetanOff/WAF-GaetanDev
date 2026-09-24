// Package cluster propage en temps réel les décisions critiques entre nœuds WAF
// (FR-20) via un bus Pub/Sub. Le modèle est en cohérence éventuelle ; si le bus
// (Redis) est indisponible, chaque nœud continue de fonctionner de manière
// autonome (dégradé mais opérationnel).
package cluster

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/gaetandev/waf/internal/middleware/access"
	"github.com/gaetandev/waf/internal/storage"
)

// Types d'événements propagés (FR-20). `degraded_mode`, réservé par
// cluster-event.schema.json, n'a pas de constante : aucun nœud ne le publie ni
// ne l'applique (coordination de la pression globale différée, cf. tasks.md).
const (
	EventBlacklistAdd  = "blacklist_add"
	EventScoreCritical = "score_critical"
	EventCircuitOpen   = "circuit_open"
)

const (
	// defaultCircuitOpenDuration borne un circuit propagé sans échéance.
	defaultCircuitOpenDuration = 300 * time.Second
	// outboxSize borne les événements en attente de publication : au-delà, ils
	// sont abandonnés plutôt que de bloquer une requête (fallback autonome).
	outboxSize     = 1024
	publishTimeout = time.Second
)

// Event est un message de synchronisation inter-nœuds.
type Event struct {
	Type string `json:"type"`
	// Node identifie l'émetteur : Redis Pub/Sub renvoie à un nœud ses propres
	// publications, qu'il ignore.
	Node   string     `json:"node,omitempty"`
	Value  string     `json:"value,omitempty"`   // IP/CIDR pour blacklist_add
	IPHash string     `json:"ip_hash,omitempty"` // pour score_critical/circuit_open
	Domain string     `json:"domain,omitempty"`
	Score  int        `json:"score,omitempty"`
	Until  *time.Time `json:"until,omitempty"` // fin d'ouverture pour circuit_open
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
	// addBlacklist applique une entrée de blacklist propagée. Par défaut elle va
	// directement au RuleSet ; avec l'API admin active, elle doit passer par
	// l'état admin (WithBlacklistApplier), seul propriétaire de la blacklist.
	addBlacklist func(value string) error
	now          func() time.Time
	node         string
	outbox       chan Event

	mu      sync.Mutex
	applied int
	dropped int
}

func NewSyncer(bus Bus, store storage.Store, rules *access.RuleSet) *Syncer {
	syncer := &Syncer{bus: bus, store: store, now: time.Now, node: newNodeID(), outbox: make(chan Event, outboxSize)}
	if rules != nil {
		syncer.addBlacklist = rules.AddBlacklist
	}
	return syncer
}

// WithBlacklistApplier remplace la destination des entrées de blacklist
// propagées. L'API admin réécrit le RuleSet entier depuis sa propre liste à
// chaque modification : une entrée posée directement dans le RuleSet en était
// effacée au premier ajout ou retrait admin local.
func (s *Syncer) WithBlacklistApplier(apply func(value string) error) {
	s.addBlacklist = apply
}

func newNodeID() string {
	raw := make([]byte, 8)
	_, _ = rand.Read(raw) // ne peut pas échouer (crypto/rand, Go 1.24+)
	return hex.EncodeToString(raw)
}

// Start s'abonne au bus et applique chaque événement entrant.
func (s *Syncer) Start(ctx context.Context) error {
	return s.bus.Subscribe(ctx, func(event Event) { s.Apply(event) })
}

// Apply mute l'état local selon l'événement reçu. Idempotent. Retourne false
// pour un événement ignoré (émis par ce nœud).
func (s *Syncer) Apply(event Event) bool {
	if event.Node != "" && event.Node == s.node {
		return false
	}
	switch event.Type {
	case EventBlacklistAdd:
		if s.addBlacklist != nil && event.Value != "" {
			_ = s.addBlacklist(event.Value)
		}
	case EventScoreCritical:
		s.applyScoreCritical(event)
	case EventCircuitOpen:
		s.applyCircuitOpen(event)
	}
	s.mu.Lock()
	s.applied++
	s.mu.Unlock()
	return true
}

// applyScoreCritical abaisse le score local au score propagé, sans jamais le
// remonter ni écraser le reste de l'état du visiteur.
func (s *Syncer) applyScoreCritical(event Event) {
	if s.store == nil || event.IPHash == "" {
		return
	}
	visitor := s.localVisitor(event)
	if visitor.Score > event.Score {
		visitor.Score = event.Score
	}
	s.store.SetVisitor(event.IPHash, visitor)
}

// applyCircuitOpen ouvre le circuit localement jusqu'à la même échéance que le
// nœud émetteur (FR-20 : « la durée du blocage est la même sur tous les
// nœuds »). Poser seulement un score, comme auparavant, ne bloquait rien.
func (s *Syncer) applyCircuitOpen(event Event) {
	if s.store == nil || event.IPHash == "" {
		return
	}
	until := s.now().Add(defaultCircuitOpenDuration)
	if event.Until != nil {
		until = *event.Until
	}
	if !until.After(s.now()) {
		return
	}
	visitor := s.localVisitor(event)
	visitor.CircuitOpen = true
	visitor.CircuitOpenUntil = &until
	if visitor.ExpiresAt.Before(until) {
		visitor.ExpiresAt = until
	}
	s.store.SetVisitor(event.IPHash, visitor)
}

// localVisitor retourne l'état local du visiteur, ou un état neuf au score
// propagé.
func (s *Syncer) localVisitor(event Event) storage.VisitorState {
	now := s.now()
	if visitor, ok := s.store.GetVisitor(event.IPHash); ok {
		visitor.LastSeen = now
		return *visitor
	}
	return storage.VisitorState{
		IPHash:    event.IPHash,
		Domain:    event.Domain,
		Score:     event.Score,
		FirstSeen: now,
		LastSeen:  now,
		ExpiresAt: now.Add(time.Hour),
	}
}

// PublishBlacklistAdd propage une entrée de blacklist (IP ou CIDR).
func (s *Syncer) PublishBlacklistAdd(value string) {
	s.Enqueue(Event{Type: EventBlacklistAdd, Value: value})
}

// PublishCircuitOpen propage l'ouverture d'un circuit jusqu'à until.
func (s *Syncer) PublishCircuitOpen(ipHash string, until time.Time) {
	s.Enqueue(Event{Type: EventCircuitOpen, IPHash: ipHash, Until: &until})
}

// PublishScoreCritical propage le score d'un visiteur très dangereux.
func (s *Syncer) PublishScoreCritical(visitor storage.VisitorState) {
	s.Enqueue(Event{Type: EventScoreCritical, IPHash: visitor.IPHash, Domain: visitor.Domain, Score: visitor.Score})
}

// Enqueue remet un événement au publicateur sans bloquer : il est appelé sur
// le chemin de requête, qui ne doit pas attendre Redis. File pleine →
// événement abandonné (cohérence éventuelle, FR-20).
func (s *Syncer) Enqueue(event Event) {
	select {
	case s.outbox <- event:
	default:
		s.mu.Lock()
		s.dropped++
		s.mu.Unlock()
	}
}

// RunPublisher publie les événements en file jusqu'à l'annulation de ctx.
func (s *Syncer) RunPublisher(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-s.outbox:
			publishCtx, cancel := context.WithTimeout(ctx, publishTimeout)
			s.Publish(publishCtx, event)
			cancel()
		}
	}
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
	event.Node = s.node
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
