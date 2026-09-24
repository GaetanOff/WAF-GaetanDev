package metrics

import (
	"fmt"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/trust"
)

var trackerEpoch = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

func TestVisitorTrackerMovesAVisitorBetweenStates(t *testing.T) {
	metrics := New()

	metrics.visitors.observe("a", trust.StateMonitored, trackerEpoch)
	metrics.visitors.observe("a", trust.StateBlocked, trackerEpoch)

	body := scrape(t, metrics)
	assertMetricContains(t, body, `waf_active_visitors 1`)
	assertMetricContains(t, body, `waf_visitors_by_state{state="MONITORED"} 0`)
	assertMetricContains(t, body, `waf_visitors_by_state{state="BLOCKED"} 1`)
}

func TestVisitorTrackerExpiresVisitorsOutsideTheWindow(t *testing.T) {
	metrics := New().WithVisitorBounds(time.Hour, 10)
	metrics.visitors.observe("old", trust.StateChallenged, trackerEpoch)

	metrics.visitors.observe("new", trust.StateTrusted, trackerEpoch.Add(time.Hour))

	body := scrape(t, metrics)
	assertMetricContains(t, body, `waf_active_visitors 1`)
	assertMetricContains(t, body, `waf_visitors_by_state{state="CHALLENGED"} 0`)
	assertMetricContains(t, body, `waf_visitors_by_state{state="TRUSTED"} 1`)
}

// La borne est ce qui empêche un DDoS distribué de faire grossir la map (et le
// temps d'observation) sans limite.
func TestVisitorTrackerIsBounded(t *testing.T) {
	metrics := New().WithVisitorBounds(time.Hour, 3)

	for i := range 100 {
		metrics.visitors.observe(fmt.Sprintf("ip-%d", i), trust.StateMonitored, trackerEpoch)
	}

	if tracked := len(metrics.visitors.entries); tracked != 3 || metrics.visitors.order.Len() != 3 {
		t.Fatalf("tracked = %d/%d, want 3", tracked, metrics.visitors.order.Len())
	}
	body := scrape(t, metrics)
	assertMetricContains(t, body, `waf_active_visitors 3`)
	assertMetricContains(t, body, `waf_visitors_by_state{state="MONITORED"} 3`)
}

// L'ancienne implémentation recomptait tous les visiteurs à chaque requête :
// le coût d'une observation ne doit plus dépendre du nombre de visiteurs suivis.
func BenchmarkVisitorTrackerObserve(b *testing.B) {
	metrics := New()
	for i := range defaultMaxVisitors {
		metrics.visitors.observe(fmt.Sprintf("ip-%d", i), trust.StateMonitored, trackerEpoch)
	}
	b.ReportAllocs()
	for b.Loop() {
		metrics.visitors.observe("ip-42", trust.StateMonitored, trackerEpoch)
	}
}
