package upstream

import (
	"context"
	"net/http"
	"time"
)

// HealthChecker sonde activement chaque upstream et met à jour son état sain
// (atomic.Bool) selon des seuils de succès/échec consécutifs (ADR-012).
type HealthChecker struct {
	pool       *Pool
	path       string
	interval   time.Duration
	timeout    time.Duration
	healthyN   int
	unhealthyN int
	client     *http.Client
}

func NewHealthChecker(pool *Pool, path string, interval, timeout time.Duration, healthyThreshold, unhealthyThreshold int) *HealthChecker {
	if path == "" {
		path = "/"
	}
	if healthyThreshold < 1 {
		healthyThreshold = 1
	}
	if unhealthyThreshold < 1 {
		unhealthyThreshold = 1
	}
	return &HealthChecker{
		pool:       pool,
		path:       path,
		interval:   interval,
		timeout:    timeout,
		healthyN:   healthyThreshold,
		unhealthyN: unhealthyThreshold,
		client:     &http.Client{Timeout: timeout},
	}
}

// Start lance une goroutine de sondage par upstream jusqu'à annulation du
// contexte.
func (h *HealthChecker) Start(ctx context.Context) {
	for _, u := range h.pool.Upstreams() {
		go h.monitor(ctx, u)
	}
}

func (h *HealthChecker) monitor(ctx context.Context, u *Upstream) {
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	successes, failures := 0, 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if h.probe(ctx, u.Address) {
				failures = 0
				successes++
				if successes >= h.healthyN {
					u.SetHealthy(true)
				}
			} else {
				successes = 0
				failures++
				if failures >= h.unhealthyN {
					u.SetHealthy(false)
				}
			}
		}
	}
}

func (h *HealthChecker) probe(ctx context.Context, address string) bool {
	reqCtx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(reqCtx, http.MethodGet, address+h.path, nil)
	if err != nil {
		return false
	}
	response, err := h.client.Do(request)
	if err != nil {
		return false
	}
	defer func() { _ = response.Body.Close() }()
	return response.StatusCode >= 200 && response.StatusCode < 400
}
