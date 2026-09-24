package antiddos

import (
	"time"

	"github.com/gaetandev/waf/internal/storage"
	"github.com/gaetandev/waf/internal/trust"
)

const (
	DefaultViolationThreshold = 5
	DefaultOpenDuration       = 300 * time.Second
	// DefaultViolationWindow borne une série de violations : le compteur repart
	// de zéro quand la précédente date de plus longtemps.
	DefaultViolationWindow         = 60 * time.Second
	DefaultGlobalRequestsPerSecond = 50000
	DefaultGlobalWindow            = time.Second
	DefaultRetryAfterSeconds       = 5
)

type CircuitBreaker struct {
	store              storage.Store
	violationThreshold int
	openDuration       time.Duration
	violationWindow    time.Duration
	onOpen             func(ipHash string, until time.Time)
	now                func() time.Time
}

func NewCircuitBreaker(store storage.Store, violationThreshold int, openDuration time.Duration) CircuitBreaker {
	if violationThreshold < 1 {
		violationThreshold = DefaultViolationThreshold
	}
	if openDuration <= 0 {
		openDuration = DefaultOpenDuration
	}
	return CircuitBreaker{
		store:              store,
		violationThreshold: violationThreshold,
		openDuration:       openDuration,
		violationWindow:    DefaultViolationWindow,
		now:                time.Now,
	}
}

func (b CircuitBreaker) IsOpen(ip string) bool {
	visitor, ok := b.store.GetVisitor(trust.HashIP(ip))
	if !ok {
		return false
	}
	if !visitor.CircuitOpen || visitor.CircuitOpenUntil == nil {
		return false
	}
	if visitor.CircuitOpenUntil.After(b.now()) {
		return true
	}

	visitor.CircuitOpen = false
	visitor.CircuitOpenUntil = nil
	visitor.ViolationCount = 0
	visitor.LastViolation = nil
	b.store.SetVisitor(visitor.IPHash, *visitor)
	return false
}

// RecordViolation compte une violation et ouvre le circuit au seuil. Les
// violations se cumulent tant que chacune suit la précédente de moins de
// violationWindow, requêtes admises intercalées ou non.
//
// Une requête admise remettait auparavant le compteur à zéro : 4 requêtes en
// 429 puis 1 requête valide, en boucle, saturaient le rate limit sans jamais
// ouvrir le circuit.
func (b CircuitBreaker) RecordViolation(ip string) storage.VisitorState {
	key := trust.HashIP(ip)
	visitor, ok := b.store.GetVisitor(key)
	if !ok {
		now := b.now()
		visitor = &storage.VisitorState{
			IPHash:    key,
			FirstSeen: now,
			LastSeen:  now,
			ExpiresAt: now.Add(b.openDuration),
		}
	}

	now := b.now()
	visitor.LastSeen = now
	if visitor.ExpiresAt.IsZero() || !visitor.ExpiresAt.After(now) {
		visitor.ExpiresAt = now.Add(b.openDuration)
	}
	if visitor.LastViolation != nil && now.Sub(*visitor.LastViolation) > b.violationWindow {
		visitor.ViolationCount = 0 // série précédente éteinte
	}
	visitor.ViolationCount++
	visitor.LastViolation = &now
	opened := false
	if visitor.ViolationCount >= b.violationThreshold {
		openUntil := now.Add(b.openDuration)
		opened = !visitor.CircuitOpen
		visitor.CircuitOpen = true
		visitor.CircuitOpenUntil = &openUntil
	}
	b.store.SetVisitor(visitor.IPHash, *visitor)
	if opened && b.onOpen != nil {
		b.onOpen(visitor.IPHash, *visitor.CircuitOpenUntil)
	}
	return *visitor
}
