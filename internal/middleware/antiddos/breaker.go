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

	b.store.UpdateVisitor(visitor.IPHash, func(current *storage.VisitorState) (storage.VisitorState, bool) {
		if current == nil || !current.CircuitOpen || current.CircuitOpenUntil == nil || current.CircuitOpenUntil.After(b.now()) {
			return storage.VisitorState{}, false // déjà refermé, ou rouvert entre-temps
		}
		closed := *current
		closed.CircuitOpen = false
		closed.CircuitOpenUntil = nil
		closed.ViolationCount = 0
		closed.LastViolation = nil
		return closed, true
	})
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
	var result storage.VisitorState
	var opened bool
	b.store.UpdateVisitor(key, func(current *storage.VisitorState) (storage.VisitorState, bool) {
		result, opened = b.countViolation(key, current)
		return result, true
	})
	if opened && b.onOpen != nil {
		b.onOpen(result.IPHash, *result.CircuitOpenUntil)
	}
	return result
}

// countViolation calcule l'état du visiteur après une violation et indique si
// elle ouvre le circuit.
func (b CircuitBreaker) countViolation(key string, current *storage.VisitorState) (storage.VisitorState, bool) {
	now := b.now()
	var visitor storage.VisitorState
	if current != nil {
		visitor = *current
	} else {
		visitor = storage.VisitorState{
			IPHash:    key,
			FirstSeen: now,
			LastSeen:  now,
			ExpiresAt: now.Add(b.openDuration),
		}
	}
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
	return visitor, opened
}
