package upstream

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"github.com/gaetandev/waf/internal/httpbody"
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
	transport  *http.Transport
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
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &HealthChecker{
		pool:       pool,
		path:       path,
		interval:   interval,
		timeout:    timeout,
		healthyN:   healthyThreshold,
		unhealthyN: unhealthyThreshold,
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			// FR-25 : le 3xx est lui-même le succès. Suivre Location jugeait la
			// santé d'une autre URL, voire d'un autre hôte.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		transport: transport,
	}
}

// SetTLSVerify applique upstream.tls_verify aux sondes, comme au proxy : les
// sondes vérifiaient toujours le certificat, si bien qu'avec tls_verify=false
// une origine HTTPS auto-signée échouait toutes ses sondes et sortait du pool
// alors que le proxy la joignait. À appeler avant Start.
func (h *HealthChecker) SetTLSVerify(verify bool) {
	h.transport.TLSClientConfig.InsecureSkipVerify = !verify
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
	wasHealthy := u.Healthy()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			healthy := h.probe(ctx, u.Address)
			// Retiré depuis la sonde précédente (échec de connexion du proxy) :
			// la remise en service compte healthy_threshold succès depuis ce
			// retrait, et non ceux d'avant, qui le rétablissaient aussitôt.
			if wasHealthy && !u.Healthy() {
				successes = 0
			}
			if healthy {
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
			wasHealthy = u.Healthy()
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
	defer func() {
		httpbody.Drain(response.Body)
		_ = response.Body.Close()
	}()
	return response.StatusCode >= 200 && response.StatusCode < 400
}
