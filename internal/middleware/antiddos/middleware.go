package antiddos

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/storage"
)

type Middleware struct {
	enabled           bool
	breaker           CircuitBreaker
	global            *GlobalRateDetector
	underAttack       *UnderAttackDetector
	onPressure        func(PressureLevel)
	retryAfterSeconds int
}

func New(breaker CircuitBreaker, global *GlobalRateDetector, retryAfterSeconds int) Middleware {
	if retryAfterSeconds < 1 {
		retryAfterSeconds = DefaultRetryAfterSeconds
	}
	return Middleware{
		enabled:           true,
		breaker:           breaker,
		global:            global,
		retryAfterSeconds: retryAfterSeconds,
	}
}

func (m Middleware) WithPressureObserver(observer func(PressureLevel)) Middleware {
	m.onPressure = observer
	return m
}

// WithCircuitOpenObserver est notifié à chaque ouverture de circuit (propagation
// cluster, FR-20).
func (m Middleware) WithCircuitOpenObserver(observer func(ipHash string, until time.Time)) Middleware {
	m.breaker.onOpen = observer
	return m
}

// WithUnderAttackDetector branche le détecteur de mode sous attaque (FR-39). En son
// absence, seule la pression globale historique est calculée.
func (m Middleware) WithUnderAttackDetector(detector *UnderAttackDetector) Middleware {
	m.underAttack = detector
	return m
}

// UnderAttackDetector expose le détecteur de mode sous attaque (nil si désactivé),
// pour brancher un observateur de transition (métrique/alerte) au câblage.
func (m Middleware) UnderAttackDetector() *UnderAttackDetector {
	return m.underAttack
}

func NewFromConfig(store storage.Store, cfg config.Config) (Middleware, error) {
	window, err := time.ParseDuration(cfg.AntiDDoS.GlobalWindow)
	if err != nil {
		return Middleware{}, fmt.Errorf("parse antiddos.global_window: %w", err)
	}
	pressure := PressureConfig{
		ElevatedMultiplier: cfg.AntiDDoS.PressureLevels.ElevatedMultiplier,
		HighMultiplier:     cfg.AntiDDoS.PressureLevels.HighMultiplier,
		CriticalMultiplier: cfg.AntiDDoS.PressureLevels.CriticalMultiplier,
	}
	middleware := New(
		NewCircuitBreaker(store, DefaultViolationThreshold, DefaultOpenDuration),
		NewGlobalRateDetector(cfg.AntiDDoS.GlobalRequestsPerSecond, window, pressure),
		cfg.AntiDDoS.RetryAfterSeconds,
	)
	middleware.enabled = cfg.AntiDDoS.Enabled

	if ua := cfg.AntiDDoS.UnderAttack; ua.Enabled {
		cooldown, err := time.ParseDuration(ua.Cooldown)
		if err != nil {
			return Middleware{}, fmt.Errorf("parse antiddos.under_attack.cooldown: %w", err)
		}
		middleware.underAttack = NewUnderAttackDetector(UnderAttackConfig{
			Enabled:         true,
			PerDomain:       ua.Scope != "global",
			TriggerPressure: PressureLevel(ua.TriggerPressure),
			ExitPressure:    PressureLevel(ua.ExitPressure),
			Cooldown:        cooldown,
			Shadow:          ua.Shadow,
			MaxDomains:      ua.MaxTrackedDomains,
			Threshold:       cfg.AntiDDoS.GlobalRequestsPerSecond,
			Window:          window,
			Pressure:        pressure,
		})
	}
	return middleware, nil
}

func (m Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.enabled {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("X-WAF-Action") == "PASS" {
			next.ServeHTTP(w, r)
			return
		}

		ip := cloudflare.RealIP(r)
		if m.breaker.IsOpen(ip) {
			// Signal déterministe (FR-35) : annoncé pour l'observabilité tout en
			// conservant le blocage immédiat.
			w.Header().Set("X-WAF-Deterministic-Trigger", "circuit_breaker")
			w.Header().Set("X-WAF-Action", "CIRCUIT_BREAK")
			w.Header().Set("X-WAF-Reason", "circuit_breaker_open")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		decision := m.recordPressure(r)
		r.Header.Set("X-WAF-Global-Pressure", string(decision.Pressure))
		if contribution := pressureContribution(decision.Pressure); contribution > 0 {
			r.Header.Set("X-WAF-Risk-rate", strconv.Itoa(contribution))
		}
		// Mode sous attaque (FR-39) : X-WAF-Under-Attack est journalisé (vrai même en
		// shadow) ; X-WAF-Under-Attack-Enforce déclenche le challenge forcé côté
		// middleware challenge (faux en shadow).
		if decision.UnderAttack {
			r.Header.Set("X-WAF-Under-Attack", "true")
		}
		if decision.Enforce {
			r.Header.Set("X-WAF-Under-Attack-Enforce", "true")
		}

		recorder := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(recorder, r)
		if isNeutralThrottle(recorder) {
			// 429 imputable au seul resserrement du WAF (pression FR-08, THROTTLE
			// FR-34) : neutre pour le breaker — le WAF ouvrirait sinon le circuit
			// à cause des 429 qu'il a lui-même provoqués.
			return
		}
		// Une requête admise ne remet pas la série à zéro : seule l'ancienneté de
		// la dernière violation l'éteint (cf. RecordViolation).
		if isViolation(recorder) {
			m.breaker.RecordViolation(ip)
		}
	})
}

func (m Middleware) recordPressure(r *http.Request) Decision {
	if m.underAttack != nil {
		decision := m.underAttack.Observe(r.Host)
		if m.onPressure != nil {
			m.onPressure(decision.Pressure)
		}
		return decision
	}
	if m.global == nil {
		return Decision{Pressure: PressureNormal}
	}
	pressure := m.global.RecordAndPressure()
	if m.onPressure != nil {
		m.onPressure(pressure)
	}
	return Decision{Pressure: pressure}
}

func pressureContribution(pressure PressureLevel) int {
	switch pressure {
	case PressureElevated:
		return 35
	case PressureHigh:
		return 60
	case PressureCritical:
		return 80
	default:
		return 0
	}
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// reasonPressureThrottle et reasonRiskThrottle sont posés par le middleware
// ratelimit sur les 429 imputables au seul resserrement de pression globale
// (FR-08) ou au débit réduit d'un visiteur classé THROTTLE (FR-34).
const (
	reasonPressureThrottle = "rate_limit_pressure"
	reasonRiskThrottle     = "rate_limit_risk_throttle"
)

func isNeutralThrottle(recorder *statusRecorder) bool {
	if recorder.statusCode != http.StatusTooManyRequests {
		return false
	}
	reason := recorder.Header().Get("X-WAF-Reason")
	return reason == reasonPressureThrottle || reason == reasonRiskThrottle
}

// isViolation ne retient que le rate limit du WAF (X-WAF-Action: RATE_LIMIT),
// seule violation du circuit breaker (FR-08). Un 429 nu venait aussi de
// l'upstream : le rate limit applicatif d'une API ouvrait le circuit et le WAF
// bannissait l'IP après cinq 429 de l'origine.
func isViolation(recorder *statusRecorder) bool {
	return recorder.Header().Get("X-WAF-Action") == "RATE_LIMIT"
}
