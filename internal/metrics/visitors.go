package metrics

import (
	"container/list"
	"sync"
	"time"

	"github.com/gaetandev/waf/internal/trust"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// defaultVisitorWindow et defaultMaxVisitors reprennent les défauts de
	// trust.score_ttl et trust.max_visitors : un visiteur est « actif » tant que
	// son score vit, et le suivi n'en retient pas plus que le store.
	defaultVisitorWindow = time.Hour
	defaultMaxVisitors   = 100000
)

// visitorStates est l'ensemble des états publiés par waf_visitors_by_state.
var visitorStates = [...]string{trust.StateTrusted, trust.StateMonitored, trust.StateChallenged, trust.StateBlocked}

// visitorTracker tient les jauges waf_active_visitors et waf_visitors_by_state.
//
// Chaque observation est en O(1) : les compteurs par état sont ajustés au
// changement d'état du visiteur au lieu d'être recomptés sur toute la map, et
// l'expiration suit une liste LRU dont on ne dépile que la queue périmée. La
// version précédente recomptait tous les visiteurs vus depuis le démarrage, à
// chaque requête et sous un verrou global : une map sans borne, parcourue en
// entier, qui effondrait le débit dès quelques centaines de milliers d'IP.
type visitorTracker struct {
	window     time.Duration
	maxEntries int
	active     prometheus.Gauge
	byState    *prometheus.GaugeVec

	mu      sync.Mutex
	entries map[string]*list.Element
	order   *list.List // front = vu le plus récemment
	counts  map[string]int
}

type trackedVisitor struct {
	ipHash   string
	state    string
	lastSeen time.Time
}

func newVisitorTracker(window time.Duration, maxEntries int, active prometheus.Gauge, byState *prometheus.GaugeVec) *visitorTracker {
	if maxEntries < 1 {
		maxEntries = 1
	}
	counts := make(map[string]int, len(visitorStates))
	for _, state := range visitorStates {
		counts[state] = 0
		byState.WithLabelValues(state).Set(0)
	}
	return &visitorTracker{
		window:     window,
		maxEntries: maxEntries,
		active:     active,
		byState:    byState,
		entries:    make(map[string]*list.Element),
		order:      list.New(),
		counts:     counts,
	}
}

// observe enregistre l'état courant d'un visiteur. Seules les jauges dont le
// compte change sont republiées.
func (t *visitorTracker) observe(ipHash string, state string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.expireLocked(now)
	if element, ok := t.entries[ipHash]; ok {
		visitor := element.Value.(*trackedVisitor)
		if visitor.state != state {
			t.addLocked(visitor.state, -1)
			t.addLocked(state, 1)
			visitor.state = state
		}
		visitor.lastSeen = now
		t.order.MoveToFront(element)
		return
	}
	t.entries[ipHash] = t.order.PushFront(&trackedVisitor{ipHash: ipHash, state: state, lastSeen: now})
	t.addLocked(state, 1)
	for len(t.entries) > t.maxEntries {
		t.removeLocked(t.order.Back())
	}
	t.active.Set(float64(len(t.entries)))
}

// expireLocked retire les visiteurs sortis de la fenêtre. La liste étant
// ordonnée par dernière observation, seule sa queue peut être périmée : le
// coût est amorti O(1) par observation.
func (t *visitorTracker) expireLocked(now time.Time) {
	if t.window <= 0 {
		return
	}
	expired := false
	for element := t.order.Back(); element != nil; element = t.order.Back() {
		if now.Sub(element.Value.(*trackedVisitor).lastSeen) < t.window {
			break
		}
		t.removeLocked(element)
		expired = true
	}
	if expired {
		t.active.Set(float64(len(t.entries)))
	}
}

func (t *visitorTracker) removeLocked(element *list.Element) {
	visitor := element.Value.(*trackedVisitor)
	t.order.Remove(element)
	delete(t.entries, visitor.ipHash)
	t.addLocked(visitor.state, -1)
}

func (t *visitorTracker) addLocked(state string, delta int) {
	t.counts[state] += delta
	t.byState.WithLabelValues(state).Set(float64(t.counts[state]))
}
