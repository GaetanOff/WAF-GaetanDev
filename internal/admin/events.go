package admin

import (
	"sync"
	"time"

	"github.com/gaetandev/waf/internal/logger"
)

const (
	// maxRecentEvents borne la mémoire du flux GET /waf/admin/events.
	maxRecentEvents = 10000
	// recentEventsRetention : le contrat annonce « max 24h en mémoire ».
	recentEventsRetention = 24 * time.Hour
)

// eventLog conserve les derniers événements de sécurité dans un tampon
// circulaire. Seules les décisions de mitigation sont retenues : à plusieurs
// milliers de requêtes par seconde, les PASS évinceraient en une seconde les
// événements que l'API sert à retrouver.
type eventLog struct {
	mu     sync.RWMutex
	events []SecurityEventSummary
	next   int
	full   bool
	now    func() time.Time
}

func newEventLog() *eventLog {
	return &eventLog{events: make([]SecurityEventSummary, maxRecentEvents), now: time.Now}
}

// RecordSecurityEvent satisfait logger.EventRecorder ; il est appelé par le
// middleware de journalisation pour chaque requête.
func (l *eventLog) RecordSecurityEvent(event logger.SecurityEvent) {
	if event.Action == logger.ActionPass {
		return
	}
	summary := SecurityEventSummary{
		Timestamp:  event.Timestamp,
		RequestID:  event.RequestID,
		IP:         event.IP, // déjà anonymisée si gdpr.anonymize_ip (FR-28)
		Domain:     event.Domain,
		Method:     event.Method,
		Path:       event.Path,
		Action:     event.Action,
		Reason:     event.Reason,
		TrustScore: event.TrustScore,
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events[l.next] = summary
	l.next = (l.next + 1) % len(l.events)
	if l.next == 0 {
		l.full = true
	}
}

// Recent retourne les événements des dernières 24 h, du plus récent au plus
// ancien, postérieurs à since (zéro = pas de borne).
func (l *eventLog) Recent(since time.Time) []SecurityEventSummary {
	cutoff := l.now().Add(-recentEventsRetention)
	if since.After(cutoff) {
		cutoff = since
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	count := l.next
	if l.full {
		count = len(l.events)
	}
	recent := make([]SecurityEventSummary, 0, count)
	for i := 1; i <= count; i++ {
		event := l.events[(l.next-i+len(l.events))%len(l.events)]
		at, err := time.Parse(time.RFC3339Nano, event.Timestamp)
		if err == nil && at.Before(cutoff) {
			break // plus ancien que la borne : le reste l'est aussi
		}
		recent = append(recent, event)
	}
	return recent
}
