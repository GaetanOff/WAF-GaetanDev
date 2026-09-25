package admin

import (
	"sync/atomic"

	"github.com/gaetandev/waf/internal/logger"
)

// trafficCounters compte les requêtes par action depuis le démarrage (GET
// /waf/stats). Les compteurs requests_* n'étaient jamais incrémentés, et
// total_requests sommait un req_count que rien n'écrivait : tout valait 0.
type trafficCounters struct {
	total       atomic.Int64
	passed      atomic.Int64
	challenged  atomic.Int64
	blocked     atomic.Int64
	rateLimited atomic.Int64
	tarpitted   atomic.Int64
}

// RecordSecurityEvent satisfait logger.EventRecorder.
func (c *trafficCounters) RecordSecurityEvent(event logger.SecurityEvent) {
	c.total.Add(1)
	switch event.Action {
	case logger.ActionPass:
		c.passed.Add(1)
	case logger.ActionChallenge:
		c.challenged.Add(1)
	case logger.ActionBlock, logger.ActionCircuitBreak, logger.ActionHoneypot:
		c.blocked.Add(1)
	case logger.ActionRateLimit:
		c.rateLimited.Add(1)
	case logger.ActionTarpit:
		c.tarpitted.Add(1)
	}
}

func (c *trafficCounters) fill(stats *WAFStats) {
	stats.TotalRequests = c.total.Load()
	stats.RequestsPassed = c.passed.Load()
	stats.RequestsChallenged = c.challenged.Load()
	stats.RequestsBlocked = c.blocked.Load()
	stats.RequestsRateLimited = c.rateLimited.Load()
	stats.RequestsTarpitted = c.tarpitted.Load()
}

// eventRecorders diffuse un événement à plusieurs puits.
type eventRecorders []logger.EventRecorder

func (r eventRecorders) RecordSecurityEvent(event logger.SecurityEvent) {
	for _, recorder := range r {
		recorder.RecordSecurityEvent(event)
	}
}
