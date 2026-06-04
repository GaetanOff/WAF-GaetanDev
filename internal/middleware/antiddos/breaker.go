package antiddos

import (
	"time"

	"github.com/gaetandev/waf/internal/storage"
	"github.com/gaetandev/waf/internal/trust"
)

const (
	DefaultViolationThreshold = 5
	DefaultOpenDuration       = 300 * time.Second
)

type CircuitBreaker struct {
	store              storage.Store
	violationThreshold int
	openDuration       time.Duration
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
	b.store.SetVisitor(visitor.IPHash, *visitor)
	return false
}

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
	visitor.ViolationCount++
	if visitor.ViolationCount >= b.violationThreshold {
		openUntil := now.Add(b.openDuration)
		visitor.CircuitOpen = true
		visitor.CircuitOpenUntil = &openUntil
	}
	b.store.SetVisitor(visitor.IPHash, *visitor)
	return *visitor
}

func (b CircuitBreaker) Reset(ip string) {
	visitor, ok := b.store.GetVisitor(trust.HashIP(ip))
	if !ok || visitor.ViolationCount == 0 {
		return
	}
	visitor.ViolationCount = 0
	b.store.SetVisitor(visitor.IPHash, *visitor)
}
