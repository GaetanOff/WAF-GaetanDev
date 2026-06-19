package metrics

import (
	"net/http"
	"sync"
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
)

type Metrics struct {
	registry        *prometheus.Registry
	requests        *prometheus.CounterVec
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
	underAttack     *prometheus.GaugeVec
	underAttackHits *prometheus.CounterVec
	clusterEvents   *prometheus.CounterVec
	tlsCertExpiry   *prometheus.GaugeVec
	mu              sync.Mutex
	visitors        map[string]string
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
		visitors: make(map[string]string),
		now:      time.Now,
	}
	registry.MustRegister(m.requests, m.blocked, m.challenged, m.duration, m.decisions, m.challengeFP, m.hardBlocks, m.verifiedBots, m.activeVisitors, m.visitorsByState, m.powDifficulty, m.globalPressure, m.underAttack, m.underAttackHits, m.clusterEvents, m.tlsCertExpiry)
	return m
}

// SetTLSCertExpiry publie l'instant d'expiration (NotAfter) du certificat d'un
// domaine en timestamp Unix (FR-33). L'alerte calcule le delta avec time().
func (m *Metrics) SetTLSCertExpiry(domain string, notAfter time.Time) {
	m.tlsCertExpiry.WithLabelValues(domain).Set(float64(notAfter.Unix()))
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
	m.underAttack.WithLabelValues(domain).Set(value)
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
		m.requests.WithLabelValues(action, r.Host).Inc()
		m.duration.WithLabelValues(action).Observe(m.now().Sub(startedAt).Seconds())
		if action == actionChallenge {
			m.challenged.WithLabelValues(r.Host, reason).Inc()
		}
		if isBlockedAction(action) {
			m.blocked.WithLabelValues(r.Host, reason).Inc()
		}
		m.observeRisk(r, recorder)
		m.observeVisitor(r, scores)
		m.observeGlobalPressure(r)
		m.observeUnderAttack(r, action)
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
	ip := cloudflare.RealIP(r)
	visitor := scores.Get(ip, r.Host)
	state := scores.State(visitor.Score)
	m.mu.Lock()
	defer m.mu.Unlock()

	m.visitors[visitor.IPHash] = state
	counts := map[string]int{
		trust.StateTrusted:    0,
		trust.StateMonitored:  0,
		trust.StateChallenged: 0,
		trust.StateBlocked:    0,
	}
	for _, visitorState := range m.visitors {
		counts[visitorState]++
	}
	m.activeVisitors.Set(float64(len(m.visitors)))
	for stateName, count := range counts {
		m.visitorsByState.WithLabelValues(stateName).Set(float64(count))
	}
}

func (m *Metrics) observeGlobalPressure(r *http.Request) {
	current := r.Header.Get("X-WAF-Global-Pressure")
	if current == "" {
		current = "normal"
	}
	for _, level := range []string{"normal", "elevated", "high", "critical"} {
		value := 0.0
		if level == current {
			value = 1
		}
		m.globalPressure.WithLabelValues(level).Set(value)
	}
}

// observeUnderAttack publie l'état du mode sous attaque par domaine (FR-39) et
// compte les requêtes forcées au challenge par ce mode.
func (m *Metrics) observeUnderAttack(r *http.Request, action string) {
	active := r.Header.Get("X-WAF-Under-Attack") == "true"
	value := 0.0
	if active {
		value = 1
	}
	m.underAttack.WithLabelValues(r.Host).Set(value)
	if active && action == actionChallenge {
		m.underAttackHits.WithLabelValues(r.Host).Inc()
	}
}

// normalizedAction dérive l'action depuis X-WAF-Action. Sans cet en-tête, le
// statut vient de l'upstream (et non d'une décision WAF) : action PASS, pour ne
// pas gonfler waf_blocked_total avec les 5xx d'origine (cf. logger.normalizedAction).
func normalizedAction(r *http.Request, recorder *statusRecorder) string {
	action := recorder.Header().Get("X-WAF-Action")
	if action == "" {
		action = r.Header.Get("X-WAF-Action")
	}
	switch action {
	case actionPass, actionChallenge, actionBlock, actionRateLimit, actionCircuitBreak, actionHoneypot:
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
