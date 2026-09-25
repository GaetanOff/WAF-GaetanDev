package metrics

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/trust"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	actionPass         = "PASS"
	actionChallenge    = "CHALLENGE"
	actionBlock        = "BLOCK"
	actionRateLimit    = "RATE_LIMIT"
	actionCircuitBreak = "CIRCUIT_BREAK"
	actionHoneypot     = "HONEYPOT"
	actionTarpit       = "TARPIT"
)

type Metrics struct {
	registry        *prometheus.Registry
	requests        *prometheus.CounterVec
	assetRequests   *prometheus.CounterVec
	blocked         *prometheus.CounterVec
	challenged      *prometheus.CounterVec
	duration        *prometheus.HistogramVec
	decisions       *prometheus.CounterVec
	challengeFP     prometheus.Counter
	hardBlocks      *prometheus.CounterVec
	verifiedBots    *prometheus.CounterVec
	activeVisitors  prometheus.Gauge
	visitorsByState *prometheus.GaugeVec
	powDifficulty   prometheus.Gauge
	globalPressure  *prometheus.GaugeVec
	pressureGauges  [len(pressureLevels)]prometheus.Gauge
	// pressureLevel est l'index publié dans pressureGauges (unknownPressure :
	// niveau inconnu, toutes à 0). pressureMu sérialise les republications.
	pressureLevel   atomic.Int32
	pressureMu      sync.Mutex
	underAttack     *prometheus.GaugeVec
	underAttackHits *prometheus.CounterVec
	clusterEvents   *prometheus.CounterVec
	tlsCertExpiry   *prometheus.GaugeVec
	cfRanges        prometheus.Gauge
	cfRangeUpdates  *prometheus.CounterVec
	storageDegraded prometheus.Gauge
	storageErrors   *prometheus.CounterVec
	alertsSent      *prometheus.CounterVec
	alertsFailed    *prometheus.CounterVec
	visitors        *visitorTracker
	domains         domainLabels
	now             func() time.Time
}

func New() *Metrics {
	registry := prometheus.NewRegistry()
	m := &Metrics{
		registry: registry,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_requests_total",
			Help: "Total WAF requests by action and domain.",
		}, []string{"action", "domain"}),
		assetRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_asset_requests_total",
			Help: "Static asset requests bypassing challenge and trust score, by domain (FR-24).",
		}, []string{"domain"}),
		blocked: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_blocked_total",
			Help: "Total WAF blocked requests by domain and reason.",
		}, []string{"domain", "reason"}),
		challenged: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_challenged_total",
			Help: "Total WAF challenged requests by domain and reason.",
		}, []string{"domain", "reason"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "waf_request_duration_seconds",
			Help:    "WAF request duration in seconds by action.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}, []string{"action"}),
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_decisions_total",
			Help: "Risk engine decisions by mitigation tier.",
		}, []string{"tier"}),
		challengeFP: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "waf_challenge_pass_after_flag_total",
			Help: "Challenges passed after a previous risk flag, proxying probable false positives.",
		}),
		hardBlocks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_hard_blocks_total",
			Help: "Risk engine hard blocks split by corroboration mode.",
		}, []string{"corroborated"}),
		verifiedBots: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_verified_bot_total",
			Help: "Verified crawler decisions by bot name.",
		}, []string{"bot"}),
		activeVisitors: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "waf_active_visitors",
			Help: "Number of active visitors seen by this WAF process.",
		}),
		visitorsByState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "waf_visitors_by_state",
			Help: "Number of active visitors by trust state.",
		}, []string{"state"}),
		powDifficulty: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "waf_challenge_pow_difficulty",
			Help: "Current adaptive proof-of-work difficulty in bits.",
		}),
		globalPressure: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "waf_global_pressure",
			Help: "Current global anti-DDoS pressure level as a one-hot gauge.",
		}, []string{"level"}),
		clusterEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_cluster_sync_events_total",
			Help: "Cluster synchronization events applied, by type.",
		}, []string{"type"}),
		tlsCertExpiry: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "waf_tls_cert_expiry_seconds",
			Help: "Unix timestamp of the TLS certificate expiry (NotAfter) per domain.",
		}, []string{"domain"}),
		underAttack: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "waf_under_attack",
			Help: "Under-attack mode active (1) or not (0) per domain (FR-39).",
		}, []string{"domain"}),
		underAttackHits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_under_attack_challenges_total",
			Help: "Requests forced to challenge by under-attack mode, per domain (FR-39).",
		}, []string{"domain"}),
		cfRanges: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "waf_cloudflare_ranges",
			Help: "Number of Cloudflare IP prefixes currently in force (FR-02).",
		}),
		cfRangeUpdates: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_cloudflare_ranges_update_total",
			Help: "Cloudflare IP range refresh attempts by result (FR-02).",
		}, []string{"result"}),
		storageDegraded: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "waf_storage_degraded",
			Help: "Storage backend serving from the local fallback store (1) or nominal (0) (ADR-021).",
		}),
		storageErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_storage_errors_total",
			Help: "Storage backend errors by operation (ADR-021).",
		}, []string{"operation"}),
		alertsSent: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_alerts_sent_total",
			Help: "Webhook alert deliveries accepted by a sink, by trigger (FR-29).",
		}, []string{"trigger"}),
		alertsFailed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_alerts_failed_total",
			Help: "Webhook alert deliveries abandoned, by trigger (FR-29).",
		}, []string{"trigger"}),
		now: time.Now,
	}
	m.visitors = newVisitorTracker(defaultVisitorWindow, defaultMaxVisitors, m.activeVisitors, m.visitorsByState)
	for i, level := range pressureLevels {
		m.pressureGauges[i] = m.globalPressure.WithLabelValues(level)
	}
	m.pressureLevel.Store(unpublishedPressure)
	registry.MustRegister(m.requests, m.assetRequests, m.blocked, m.challenged, m.duration, m.decisions, m.challengeFP, m.hardBlocks, m.verifiedBots, m.activeVisitors, m.visitorsByState, m.powDifficulty, m.globalPressure, m.underAttack, m.underAttackHits, m.clusterEvents, m.tlsCertExpiry, m.cfRanges, m.cfRangeUpdates, m.storageDegraded, m.storageErrors, m.alertsSent, m.alertsFailed)
	// La liste compilée est en vigueur au démarrage : publier son cardinal tout
	// de suite évite une jauge à 0 qui se lirait comme « aucune plage connue ».
	m.cfRanges.Set(float64(len(cloudflare.Ranges())))
	return m
}

// WithVisitorBounds aligne le suivi des visiteurs actifs sur la configuration
// du trust score : un visiteur sort des jauges quand son score expirerait
// (trust.score_ttl), et le suivi n'en retient pas plus que trust.max_visitors.
func (m *Metrics) WithVisitorBounds(window time.Duration, maxVisitors int) *Metrics {
	m.visitors = newVisitorTracker(window, maxVisitors, m.activeVisitors, m.visitorsByState)
	return m
}

// WithDomains déclare les hôtes de domains[] : seuls eux portent leur propre
// label domain, les autres sont comptés sous undeclaredDomain.
func (m *Metrics) WithDomains(hosts []string) *Metrics {
	m.domains = newDomainLabels(hosts)
	return m
}

// SetTLSCertExpiry publie l'instant d'expiration (NotAfter) du certificat d'un
// domaine en timestamp Unix (FR-33). L'alerte calcule le delta avec time().
func (m *Metrics) SetTLSCertExpiry(domain string, notAfter time.Time) {
	m.tlsCertExpiry.WithLabelValues(domain).Set(float64(notAfter.Unix()))
}

// IncAssetRequest compte une requête d'asset statique bypassée (FR-24). Le
// ratio avec waf_requests_total sert à ajuster static_assets.
func (m *Metrics) IncAssetRequest(host string) {
	m.assetRequests.WithLabelValues(m.domains.label(host)).Inc()
}

// SetPowDifficulty publie la difficulté courante du PoW adaptatif (FR-14).
func (m *Metrics) SetPowDifficulty(bits int) {
	m.powDifficulty.Set(float64(bits))
}

// SetUnderAttack publie l'état du mode sous attaque d'un scope sur transition
// (FR-39), pour refléter immédiatement une sortie même sans trafic ultérieur.
func (m *Metrics) SetUnderAttack(domain string, active bool) {
	value := 0.0
	if active {
		value = 1
	}
	if domain != globalScope {
		domain = m.domains.label(domain)
	}
	m.underAttack.WithLabelValues(domain).Set(value)
}

// SetCloudflareRanges publie le nombre de plages IP Cloudflare en vigueur
// (FR-02). Une chute de ce cardinal après un rafraîchissement est le signal
// qu'une liste plus étroite a été adoptée.
func (m *Metrics) SetCloudflareRanges(count int) {
	m.cfRanges.Set(float64(count))
}

// IncCloudflareRangeUpdate compte une tentative de rafraîchissement des plages
// Cloudflare par issue ("success" / "error"). Sans ce compteur, un
// rafraîchissement qui échoue en boucle serait invisible : le WAF continue de
// servir avec l'ancienne liste, donc rien ne se dégrade visiblement (FR-02).
func (m *Metrics) IncCloudflareRangeUpdate(result string) {
	m.cfRangeUpdates.WithLabelValues(result).Inc()
}

// SetStorageDegraded publie l'état du backend de stockage : 1 quand le nœud sert
// son état local faute de Redis (ADR-021), 0 en nominal.
func (m *Metrics) SetStorageDegraded(degraded bool) {
	value := 0.0
	if degraded {
		value = 1
	}
	m.storageDegraded.Set(value)
}

// IncStorageError compte une erreur du backend de stockage par opération (ADR-021).
func (m *Metrics) IncStorageError(operation string) {
	m.storageErrors.WithLabelValues(operation).Inc()
}

// AlertSent compte une alerte acceptée par un sink (FR-29). Le trigger est
// une valeur de l'enum d'alert.schema.json : cardinalité bornée.
func (m *Metrics) AlertSent(trigger string) {
	m.alertsSent.WithLabelValues(trigger).Inc()
}

// AlertFailed compte une alerte abandonnée pour un sink (FR-29).
func (m *Metrics) AlertFailed(trigger string) {
	m.alertsFailed.WithLabelValues(trigger).Inc()
}

// WithAlertsPending publie waf_alerts_pending, le nombre d'alertes en attente
// d'envoi, lu à chaque scrape. À appeler une fois, quand l'alerting est actif.
func (m *Metrics) WithAlertsPending(pending func() int) *Metrics {
	m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "waf_alerts_pending",
		Help: "Webhook alerts waiting to be delivered (FR-29).",
	}, func() float64 { return float64(pending()) }))
	return m
}

// IncClusterSync compte un événement de synchronisation cluster appliqué (FR-20).
func (m *Metrics) IncClusterSync(eventType string) {
	m.clusterEvents.WithLabelValues(eventType).Inc()
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *Metrics) Middleware(scores *trust.ScoreManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedAt := m.now()
		recorder := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(recorder, r)

		action := normalizedAction(r, recorder)
		reason := wafReason(r, recorder)
		domain := m.domains.label(r.Host)
		m.requests.WithLabelValues(action, domain).Inc()
		m.duration.WithLabelValues(action).Observe(m.now().Sub(startedAt).Seconds())
		if action == actionChallenge {
			m.challenged.WithLabelValues(domain, reason).Inc()
		}
		if isBlockedAction(action) {
			m.blocked.WithLabelValues(domain, reason).Inc()
		}
		m.observeRisk(r, recorder)
		m.observeVisitor(r, scores)
		m.observeGlobalPressure(r)
		m.observeUnderAttack(r, action, domain)
	})
}

func (m *Metrics) observeRisk(r *http.Request, recorder *statusRecorder) {
	decision := headerValue(r, recorder, "X-WAF-Risk-Decision")
	if decision != "" {
		m.decisions.WithLabelValues(decision).Inc()
	}
	if headerValue(r, recorder, "X-WAF-Challenge-Pass-After-Flag") == "true" {
		m.challengeFP.Inc()
	}
	if decision == actionBlock {
		corroborated := headerValue(r, recorder, "X-WAF-Risk-Corroborated")
		if corroborated != "true" {
			corroborated = "false"
		}
		m.hardBlocks.WithLabelValues(corroborated).Inc()
	}
	if bot := headerValue(r, recorder, "X-WAF-Risk-Verified-Bot"); bot != "" {
		m.verifiedBots.WithLabelValues(bot).Inc()
	}
}

func (m *Metrics) observeVisitor(r *http.Request, scores *trust.ScoreManager) {
	if scores == nil {
		return
	}
	visitor := scores.Peek(cloudflare.RealIP(r), r.Host)
	m.visitors.observe(visitor.IPHash, scores.State(visitor.Score), m.now())
}

// pressureLevels sont les niveaux de waf_global_pressure, jauge one-hot.
var pressureLevels = [...]string{"normal", "elevated", "high", "critical"}

const (
	unknownPressure     = -1 // niveau hors de pressureLevels : toutes à 0
	unpublishedPressure = -2 // aucune requête observée

	// headerGlobalPressure est X-WAF-Global-Pressure sous sa forme canonique :
	// Header.Get n'a pas à la recalculer (une allocation par appel).
	headerGlobalPressure = "X-Waf-Global-Pressure"
)

// observeGlobalPressure ne republie la jauge one-hot qu'au changement de
// niveau : quatre WithLabelValues().Set() par requête (recherche de série
// par label) pour une valeur qui ne change qu'avec la pression.
func (m *Metrics) observeGlobalPressure(r *http.Request) {
	current := r.Header.Get(headerGlobalPressure)
	if current == "" {
		current = "normal"
	}
	level := int32(unknownPressure)
	for i, name := range pressureLevels {
		if name == current {
			level = int32(i)
			break
		}
	}
	if m.pressureLevel.Load() == level {
		return
	}
	m.pressureMu.Lock()
	defer m.pressureMu.Unlock()
	for i, gauge := range m.pressureGauges {
		value := 0.0
		if int32(i) == level {
			value = 1
		}
		gauge.Set(value)
	}
	m.pressureLevel.Store(level)
}

// observeUnderAttack publie l'état du mode sous attaque par domaine (FR-39) et
// compte les requêtes forcées au challenge par ce mode.
func (m *Metrics) observeUnderAttack(r *http.Request, action string, domain string) {
	active := r.Header.Get("X-WAF-Under-Attack") == "true"
	value := 0.0
	if active {
		value = 1
	}
	m.underAttack.WithLabelValues(domain).Set(value)
	if active && action == actionChallenge {
		m.underAttackHits.WithLabelValues(domain).Inc()
	}
}

// normalizedAction dérive l'action depuis X-WAF-Action. Sans cet en-tête, le
// statut vient de l'upstream (et non d'une décision WAF) : action PASS, pour ne
// pas gonfler waf_blocked_total avec les 5xx d'origine (cf. logger.normalizedAction).
// TARPIT n'est retenu que sur la réponse, posé par le tarpit qui la sert : sur
// la requête, c'est une classification qui atteint l'upstream sans déception.
func normalizedAction(r *http.Request, recorder *statusRecorder) string {
	action := recorder.Header().Get("X-WAF-Action")
	if action == "" {
		action = r.Header.Get("X-WAF-Action")
		if action == actionTarpit {
			return actionPass
		}
	}
	switch action {
	case actionPass, actionChallenge, actionBlock, actionRateLimit, actionCircuitBreak, actionHoneypot, actionTarpit:
		return action
	default:
		return actionPass
	}
}

func wafReason(r *http.Request, recorder *statusRecorder) string {
	if value := recorder.Header().Get("X-WAF-Reason"); value != "" {
		return value
	}
	if value := r.Header.Get("X-WAF-Reason"); value != "" {
		return value
	}
	return "none"
}

func headerValue(r *http.Request, recorder *statusRecorder, name string) string {
	if value := recorder.Header().Get(name); value != "" {
		return value
	}
	return r.Header.Get(name)
}

func isBlockedAction(action string) bool {
	return action == actionBlock || action == actionCircuitBreak || action == actionHoneypot
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *statusRecorder) Write(body []byte) (int, error) {
	return r.ResponseWriter.Write(body)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
