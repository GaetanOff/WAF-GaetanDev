// Package behavioral calcule un score d'anomalie comportementale par visiteur
// (FR-12, ADR-009) à partir des dernières requêtes (path + timestamp). Le calcul
// est asynchrone (NFR-07) : la requête courante est enfilée pour traitement, et
// le score déjà calculé est appliqué à la requête en cours via le moteur de
// risque (famille `behavioral`).
package behavioral

import (
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/trust"
)

const (
	headerRiskBehavioral = "X-WAF-Risk-behavioral"

	defaultMaxRecords = 50
	minRecords        = 5

	// Contributions par signal (sommées, bornées à 100).
	contribTimeUniformity = 30
	contribPathRepetition = 25
	contribVelocity       = 25
	contribAssetAbsence   = 20
	contribAlphabetical   = 20
)

type record struct {
	path string
	at   time.Time
}

type event struct {
	ipHash string
	path   string
	at     time.Time
}

// Tracker maintient un ring buffer par visiteur et un score d'anomalie courant.
type Tracker struct {
	mu      sync.RWMutex
	buffers map[string][]record
	scores  map[string]int
	max     int

	queue  chan event
	stop   chan struct{}
	done   chan struct{}
	closed bool
	now    func() time.Time
}

func New(maxRecords int) *Tracker {
	if maxRecords <= 0 {
		maxRecords = defaultMaxRecords
	}
	t := &Tracker{
		buffers: make(map[string][]record),
		scores:  make(map[string]int),
		max:     maxRecords,
		queue:   make(chan event, 1024),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		now:     time.Now,
	}
	go t.worker()
	return t
}

func (t *Tracker) worker() {
	defer close(t.done)
	for {
		select {
		case e := <-t.queue:
			t.ingest(e)
		case <-t.stop:
			return
		}
	}
}

// Observe enfile la requête courante pour traitement asynchrone (non bloquant).
func (t *Tracker) Observe(ipHash string, path string) {
	select {
	case t.queue <- event{ipHash: ipHash, path: path, at: t.now()}:
	default:
		// File pleine : on laisse tomber l'événement plutôt que de bloquer la
		// requête (NFR-07 : ne jamais bloquer le pipeline).
	}
}

// Score retourne le dernier score d'anomalie calculé pour ce visiteur.
func (t *Tracker) Score(ipHash string) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.scores[ipHash]
}

// ingest ajoute un enregistrement au ring buffer et recalcule le score.
func (t *Tracker) ingest(e event) {
	t.mu.Lock()
	defer t.mu.Unlock()

	buffer := append(t.buffers[e.ipHash], record{path: e.path, at: e.at})
	if len(buffer) > t.max {
		buffer = buffer[len(buffer)-t.max:]
	}
	t.buffers[e.ipHash] = buffer
	t.scores[e.ipHash] = computeAnomaly(buffer)
}

// Close arrête le worker et attend sa terminaison.
func (t *Tracker) Close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	t.mu.Unlock()
	// On ferme `stop` (jamais `queue`) : Observe peut être appelé pendant le
	// shutdown sans risque de panic « send on closed channel ».
	close(t.stop)
	<-t.done
}

// Handler publie la contribution `behavioral` (score précédent) et enfile la
// requête courante pour le calcul suivant.
func (t *Tracker) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-WAF-Action") == "PASS" {
			next.ServeHTTP(w, r)
			return
		}
		ipHash := trust.HashIP(cloudflare.RealIP(r))
		if score := t.Score(ipHash); score > 0 {
			r.Header.Set(headerRiskBehavioral, strconv.Itoa(score))
		}
		t.Observe(ipHash, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// computeAnomaly évalue les 6 signaux comportementaux et retourne un score
// [0..100] (0 = humain, 100 = bot). Sous minRecords, retourne 0 (confiance
// insuffisante).
func computeAnomaly(records []record) int {
	if len(records) < minRecords {
		return 0
	}

	score := 0
	if isTimeUniform(records) {
		score += contribTimeUniformity
	}
	if maxConsecutiveRepeat(records) > 10 {
		score += contribPathRepetition
	}
	if isHighVelocity(records) {
		score += contribVelocity
	}
	if isAssetAbsent(records) {
		score += contribAssetAbsence
	}
	if isAlphabetical(records) {
		score += contribAlphabetical
	}

	if score > 100 {
		score = 100
	}
	return score
}

// isTimeUniform : intervalles inter-requêtes très réguliers (coefficient de
// variation faible) → comportement machine.
func isTimeUniform(records []record) bool {
	intervals := make([]float64, 0, len(records)-1)
	for i := 1; i < len(records); i++ {
		intervals = append(intervals, records[i].at.Sub(records[i-1].at).Seconds())
	}
	if len(intervals) < 3 {
		return false
	}
	mean := 0.0
	for _, v := range intervals {
		mean += v
	}
	mean /= float64(len(intervals))
	if mean <= 0 {
		return true // requêtes simultanées = machine
	}
	variance := 0.0
	for _, v := range intervals {
		variance += (v - mean) * (v - mean)
	}
	stddev := math.Sqrt(variance / float64(len(intervals)))
	return stddev/mean < 0.1
}

func maxConsecutiveRepeat(records []record) int {
	best, current := 1, 1
	for i := 1; i < len(records); i++ {
		if records[i].path == records[i-1].path {
			current++
			if current > best {
				best = current
			}
		} else {
			current = 1
		}
	}
	return best
}

// isHighVelocity : beaucoup de paths uniques sur une fenêtre courte → crawler.
func isHighVelocity(records []record) bool {
	unique := make(map[string]struct{}, len(records))
	for _, r := range records {
		unique[r.path] = struct{}{}
	}
	span := records[len(records)-1].at.Sub(records[0].at).Seconds()
	return len(unique) >= 20 && span < 5
}

// isAssetAbsent : requêtes HTML sans requêtes d'assets associées → headless.
func isAssetAbsent(records []record) bool {
	htmlCount, assetCount := 0, 0
	for _, r := range records {
		if isAssetPath(r.path) {
			assetCount++
		} else {
			htmlCount++
		}
	}
	return htmlCount >= 5 && assetCount == 0
}

// isAlphabetical : paths uniques explorés dans l'ordre alphabétique → crawler
// systématique.
func isAlphabetical(records []record) bool {
	paths := make([]string, 0, len(records))
	seen := make(map[string]struct{})
	for _, r := range records {
		if _, ok := seen[r.path]; ok {
			continue
		}
		seen[r.path] = struct{}{}
		paths = append(paths, r.path)
	}
	if len(paths) < 5 {
		return false
	}
	return sort.SliceIsSorted(paths, func(i, j int) bool { return paths[i] < paths[j] })
}

func isAssetPath(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ico"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
