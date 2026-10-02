package upstream

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testProbeInterval = 5 * time.Millisecond
	testProbeTimeout  = 200 * time.Millisecond
	testWaitDeadline  = 2 * time.Second
)

func newTestChecker(t *testing.T, address string, healthyN, unhealthyN int) (*HealthChecker, *Upstream) {
	t.Helper()
	member := &Upstream{Address: address}
	pool := NewPool(StrategyRoundRobin, []*Upstream{member})
	return NewHealthChecker(pool, "/healthz", testProbeInterval, testProbeTimeout, healthyN, unhealthyN), member
}

func waitHealthy(t *testing.T, member *Upstream, want bool) {
	t.Helper()
	deadline := time.Now().Add(testWaitDeadline)
	for member.Healthy() != want {
		if time.Now().After(deadline) {
			t.Fatalf("Healthy() = %v after %s, want %v", member.Healthy(), testWaitDeadline, want)
		}
		time.Sleep(testProbeInterval)
	}
}

func TestNewHealthCheckerAppliesDefaults(t *testing.T) {
	checker := NewHealthChecker(NewPool("", nil), "", time.Second, time.Second, 0, -1)

	if checker.path != "/" || checker.healthyN != 1 || checker.unhealthyN != 1 {
		t.Fatalf("path=%q healthyN=%d unhealthyN=%d, want \"/\", 1, 1", checker.path, checker.healthyN, checker.unhealthyN)
	}
}

// FR-25 : 2xx ou 3xx = succès, un autre statut ou une erreur réseau = échec.
func TestProbeStatusClasses(t *testing.T) {
	cases := []struct {
		status int
		want   bool
	}{
		{http.StatusOK, true},
		{http.StatusNoContent, true},
		{http.StatusNotModified, true},
		{http.StatusNotFound, false},
		{http.StatusInternalServerError, false},
		{http.StatusServiceUnavailable, false},
	}
	for _, tc := range cases {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/healthz" || r.Method != http.MethodGet {
				t.Errorf("probe = %s %s, want GET /healthz", r.Method, r.URL.Path)
			}
			w.WriteHeader(tc.status)
		}))
		checker, member := newTestChecker(t, server.URL, 1, 1)

		if got := checker.probe(context.Background(), member.Address); got != tc.want {
			t.Errorf("probe(status %d) = %v, want %v", tc.status, got, tc.want)
		}
		server.Close()
	}
}

func TestProbeFailsOnUnreachableUpstream(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	address := server.URL
	server.Close()
	checker, member := newTestChecker(t, address, 1, 1)

	if checker.probe(context.Background(), member.Address) {
		t.Fatal("probe of a closed listener must fail")
	}
}

// FR-25 : une sonde qui dépasse health_check.timeout compte comme un échec.
func TestProbeFailsOnTimeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)
	checker, member := newTestChecker(t, server.URL, 1, 1)

	if checker.probe(context.Background(), member.Address) {
		t.Fatal("probe slower than the timeout must fail")
	}
}

// FR-25 : le 3xx est le succès ; suivre Location jugeait la santé d'une autre
// URL (ici injoignable), et faisait sortir du pool un membre sain.
func TestProbeDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		followed.Store(true)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/login", http.StatusFound)
	}))
	defer server.Close()
	checker, member := newTestChecker(t, server.URL, 1, 1)

	if !checker.probe(context.Background(), member.Address) {
		t.Fatal("a 302 from the upstream is a successful probe")
	}
	if followed.Load() {
		t.Fatal("the probe must not follow the redirect")
	}
}

// FR-25 : la sonde applique upstream.tls_verify, comme le proxy.
func TestProbeHonorsTLSVerify(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	verifying, member := newTestChecker(t, server.URL, 1, 1)
	if verifying.probe(context.Background(), member.Address) {
		t.Fatal("with TLS verification, a self-signed upstream must fail the probe")
	}

	skipping, member := newTestChecker(t, server.URL, 1, 1)
	skipping.SetTLSVerify(false)
	if !skipping.probe(context.Background(), member.Address) {
		t.Fatal("with upstream.tls_verify=false, a self-signed upstream must pass the probe")
	}
}

// FR-25 : retrait après unhealthy_threshold échecs consécutifs, retour après
// healthy_threshold succès consécutifs.
func TestMonitorAppliesThresholds(t *testing.T) {
	var failing atomic.Bool
	failing.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	checker, member := newTestChecker(t, server.URL, 2, 3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	checker.Start(ctx)

	waitHealthy(t, member, false)
	failing.Store(false)
	waitHealthy(t, member, true)
}

// Arrêt : les sondes s'arrêtent avec le contexte du WAF.
func TestMonitorStopsWithContext(t *testing.T) {
	var probes atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probes.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	checker, _ := newTestChecker(t, server.URL, 1, 1)
	ctx, cancel := context.WithCancel(context.Background())

	checker.Start(ctx)
	deadline := time.Now().Add(testWaitDeadline)
	for probes.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no probe was sent")
		}
		time.Sleep(testProbeInterval)
	}
	cancel()
	time.Sleep(10 * testProbeInterval) // une sonde en vol peut encore se terminer
	settled := probes.Load()
	time.Sleep(10 * testProbeInterval)

	if got := probes.Load(); got != settled {
		t.Fatalf("probes kept running after cancel: %d -> %d", settled, got)
	}
}

// FR-25 : un membre retiré par le proxy (échec de connexion) n'est remis en
// service qu'après healthy_threshold succès comptés depuis le retrait ; ceux
// d'avant le rétablissaient dès la sonde suivante.
func TestMonitorCountsSuccessesSinceEjection(t *testing.T) {
	var probes atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probes.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(origin.Close)
	checker, member := newTestChecker(t, origin.URL, 3, 3)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	checker.Start(ctx)

	deadline := time.Now().Add(testWaitDeadline)
	for probes.Load() < 5 {
		if time.Now().After(deadline) {
			t.Fatal("probes did not run")
		}
		time.Sleep(testProbeInterval)
	}
	before := probes.Load()
	member.SetHealthy(false)
	waitHealthy(t, member, true)

	// La sonde en cours au moment du retrait compte pour un succès.
	if after := probes.Load() - before; after < 2 {
		t.Fatalf("readmitted after %d probe(s) since the ejection, want at least healthy_threshold - 1 = 2", after)
	}
}
