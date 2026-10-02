package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/upstream"
)

func newPoolHandler(t *testing.T, address string) (*Handler, *upstream.Upstream) {
	t.Helper()
	handler := newTestHandler(t, address, nil)
	member := &upstream.Upstream{Address: address}
	pool := upstream.NewPool(upstream.StrategyRoundRobin, []*upstream.Upstream{member})
	if err := handler.WithPool(pool, false, 10, 2*time.Second, false); err != nil {
		t.Fatalf("WithPool() error = %v", err)
	}
	return handler, member
}

// Un client qui annule sa requête n'est pas une panne de l'upstream : il ne
// doit pas retirer le membre du pool (FR-25).
func TestPoolKeepsMemberHealthyWhenClientCancels(t *testing.T) {
	release := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(origin.Close)
	t.Cleanup(func() { close(release) })
	handler, member := newPoolHandler(t, origin.URL)

	ctx, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet, "http://example.test/slow", nil).WithContext(ctx)
	time.AfterFunc(50*time.Millisecond, cancel)
	handler.ServeHTTP(httptest.NewRecorder(), request)

	if !member.Healthy() {
		t.Fatal("a client cancellation marked the upstream unhealthy")
	}
}

// Une vraie erreur de proxy (connexion refusée) retire toujours le membre
// immédiatement (FR-25, « Erreur de proxy — retrait immédiat »).
func TestPoolMarksMemberUnhealthyOnConnectionError(t *testing.T) {
	origin := httptest.NewServer(http.NotFoundHandler())
	address := origin.URL
	origin.Close()
	handler, member := newPoolHandler(t, address)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://example.test/", nil))

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", response.Code)
	}
	if member.Healthy() {
		t.Fatal("a refused connection must take the member out of service")
	}
}

// FR-25 : un délai de réponse dépassé n'est pas un échec de connexion. Une
// seule requête lente retirait le membre, et un pool d'un membre répondait
// « no healthy upstream » à tous.
func TestPoolKeepsMemberHealthyOnResponseTimeout(t *testing.T) {
	release := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(origin.Close)
	t.Cleanup(func() { close(release) })
	handler := newTestHandler(t, origin.URL, nil)
	member := &upstream.Upstream{Address: origin.URL}
	pool := upstream.NewPool(upstream.StrategyRoundRobin, []*upstream.Upstream{member})
	if err := handler.WithPool(pool, false, 10, 100*time.Millisecond, false); err != nil {
		t.Fatalf("WithPool() error = %v", err)
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://example.test/slow", nil))

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", response.Code)
	}
	if !member.Healthy() {
		t.Fatal("a response timeout marked the upstream unhealthy")
	}
}
