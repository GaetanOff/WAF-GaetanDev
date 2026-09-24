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
	headerAction         = "X-WAF-Action"
	headerReason         = "X-WAF-Reason"
	actionPass           = "PASS"
	// reasonStaticAsset est posé par internal/staticassets (FR-24) sur les
	// requêtes d'assets qu'il marque PASS.
	reasonStaticAsset = "static_asset"

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
	// asset marque une requête d'asset statique reconnue par le bypass FR-24,
	// dont l'extension peut sortir de la liste de isAssetPath.
	asset bool
}

type event struct {
	ipHash string
	path   string
	at     time.Time
	asset  bool
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
	t.enqueue(event{ipHash: ipHash, path: path, at: t.now()})
}

// ObserveAsset enfile une requête d'asset statique. Elle ne sert qu'au signal
// d'absence d'assets : les autres signaux ne portent que sur les pages.
func (t *Tracker) ObserveAsset(ipHash string, path string) {
	t.enqueue(event{ipHash: ipHash, path: path, at: t.now(), asset: true})
}

func (t *Tracker) enqueue(e event) {
	select {
	case t.queue <- e:
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

	buffer := append(t.buffers[e.ipHash], record{path: e.path, at: e.at, asset: e.asset})
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
//
// Les assets statiques arrivent marqués PASS par le bypass FR-24, monté en
// amont. Ils sont tout de même enregistrés : sans eux, le signal d'absence
// d'assets classait tout humain ayant vu 5 pages comme navigateur headless.
func (t *Tracker) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerAction) == actionPass {
			if r.Header.Get(headerReason) == reasonStaticAsset {
				t.ObserveAsset(trust.HashIP(cloudflare.RealIP(r)), r.URL.Path)
			}
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

// computeAnomaly évalue les signaux comportementaux et retourne un score
// [0..100] (0 = humain, 100 = bot). Sous minRecords pages, retourne 0
// (confiance insuffisante).
//
// Seule l'absence d'assets regarde les assets : les rafales de sous-requêtes
// d'un chargement de page fausseraient la régularité, la vélocité et l'ordre
// alphabétique, qui décrivent la navigation entre pages.
func computeAnomaly(records []record) int {
	pages := pageRecords(records)
	if len(pages) < minRecords {
		return 0
	}

	score := 0
	if isTimeUniform(pages) {
		score += contribTimeUniformity
	}
	if maxConsecutiveRepeat(pages) > 10 {
		score += contribPathRepetition
	}
	if isHighVelocity(pages) {
		score += contribVelocity
	}
	if isAssetAbsent(records) {
		score += contribAssetAbsence
	}
	if isAlphabetical(pages) {
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

func pageRecords(records []record) []record {
	pages := make([]record, 0, len(records))
	for _, r := range records {
		if !r.isAsset() {
			pages = append(pages, r)
		}
	}
	return pages
}

// isAssetAbsent : requêtes HTML sans requêtes d'assets associées → headless.
func isAssetAbsent(records []record) bool {
	htmlCount, assetCount := 0, 0
	for _, r := range records {
		if r.isAsset() {
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

func (r record) isAsset() bool {
	return r.asset || isAssetPath(r.path)
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
