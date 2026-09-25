package risk

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/trust"
)

func TestMiddlewareBlocksDeterministicTriggerBeforeProxy(t *testing.T) {
	middleware, _, store := newTestRiskMiddleware(t)
	defer store.Close()
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "1.2.3.4:1234"
	request.Header.Set(headerDeterministicTrigger, string(TriggerBlacklist))
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("proxy should not be called")
	})).ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if response.Header().Get(headerAction) != string(DecisionBlock) {
		t.Fatalf("X-WAF-Action = %q, want BLOCK", response.Header().Get(headerAction))
	}
	if response.Header().Get(headerReason) != "risk_deterministic_blacklist" {
		t.Fatalf("X-WAF-Reason = %q, want deterministic blacklist", response.Header().Get(headerReason))
	}
}

func TestMiddlewareBlocksCorroboratedHeuristicRisk(t *testing.T) {
	middleware, _, store := newTestRiskMiddleware(t)
	defer store.Close()
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "1.2.3.4:1234"
	setHighRiskHeaders(request)
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("proxy should not be called")
	})).ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if response.Header().Get(headerReason) != "risk_heuristic" {
		t.Fatalf("X-WAF-Reason = %q, want risk_heuristic", response.Header().Get(headerReason))
	}
}

func TestMiddlewareInjectsCondensedRiskAssessmentHeaders(t *testing.T) {
	middleware, _, store := newTestRiskMiddleware(t)
	defer store.Close()
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "1.2.3.4:1234"
	request.Header.Set("X-WAF-Risk-Behavioral", "45")
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerRiskScore) == "" {
			t.Fatal("request missing X-WAF-Risk-Score")
		}
		if r.Header.Get(headerRiskDecision) == "" {
			t.Fatal("request missing X-WAF-Risk-Decision")
		}
		if r.Header.Get(headerRiskConfidence) == "" {
			t.Fatal("request missing X-WAF-Risk-Confidence")
		}
		if r.Header.Get(headerScoreDelta) == "" {
			t.Fatal("request missing X-WAF-Score-Delta")
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}

func TestMiddlewareAllowsStrongHumanProofDespiteHighHeuristicRisk(t *testing.T) {
	middleware, humans, store := newTestRiskMiddleware(t)
	defer store.Close()
	humans.GrantChallengePass("1.2.3.4", "example.test", testFPHash)
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "1.2.3.4:1234"
	request.Header.Set(headerFingerprintHash, testFPHash)
	setHighRiskHeaders(request)
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerRiskDecision) != string(DecisionAllow) {
			t.Fatalf("X-WAF-Risk-Decision = %q, want ALLOW", r.Header.Get(headerRiskDecision))
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}

func TestMiddlewareShadowModeLogsDecisionWithoutApplyingBlock(t *testing.T) {
	middleware, _, store := newTestRiskMiddleware(t)
	defer store.Close()
	middleware.shadow = true
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "1.2.3.4:1234"
	setHighRiskHeaders(request)
	response := httptest.NewRecorder()

	middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerRiskShadowMode) != "true" {
			t.Fatalf("X-WAF-Risk-Shadow-Mode = %q, want true", r.Header.Get(headerRiskShadowMode))
		}
		if r.Header.Get(headerRiskDecision) != string(DecisionBlock) {
			t.Fatalf("X-WAF-Risk-Decision = %q, want BLOCK", r.Header.Get(headerRiskDecision))
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
	if response.Header().Get(headerAction) == string(DecisionBlock) {
		t.Fatal("shadow mode must not apply BLOCK response")
	}
}

// FR-34 : THROTTLE réduit le débit du visiteur. Le moteur le signale au rate
// limit (monté en amont) ; en shadow, aucune mitigation n'est appliquée.
func TestMiddlewareThrottleDecisionReachesTheRateLimiter(t *testing.T) {
	for _, shadow := range []bool{false, true} {
		middleware, _, store := newTestRiskMiddleware(t)
		defer store.Close()
		middleware.shadow = shadow
		middleware.decision.Tiers = DecisionTiers{Observe: 1, Throttle: 2, Challenge: 99, Tarpit: 99, Block: 100}
		var throttled []string
		middleware.WithThrottle(func(ip string) { throttled = append(throttled, ip) })
		request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
		request.RemoteAddr = "1.2.3.4:1234"

		middleware.Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			if r.Header.Get(headerRiskDecision) != string(DecisionThrottle) {
				t.Fatalf("X-WAF-Risk-Decision = %q, want THROTTLE", r.Header.Get(headerRiskDecision))
			}
		})).ServeHTTP(httptest.NewRecorder(), request)

		want := 1
		if shadow {
			want = 0
		}
		if len(throttled) != want || (want == 1 && throttled[0] != "1.2.3.4") {
			t.Fatalf("shadow=%v: throttled = %v, want %d call(s) for 1.2.3.4", shadow, throttled, want)
		}
	}
}

func newTestRiskMiddleware(t *testing.T) (*Middleware, *HumanTrustManager, *memory.Store) {
	t.Helper()

	store := memory.New(100)
	cfg := config.Default()
	cfg.Version = "1.0"
	cfg.Server.Listen = ":0"
	cfg.Upstream.Address = "http://example.test"
	cfg.Challenge.Enabled = false
	cfg.Admin.Enabled = false
	cfg.RiskEngine.Tiers.Tarpit = 70
	cfg.RiskEngine.Tiers.Block = 75
	scores, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	humans := NewHumanTrustManager(store, HumanCreditConfig{
		ChallengePassed:   -40,
		StableFingerprint: -15,
		StickyTrustTTL:    30 * time.Minute,
	})
	middleware := NewMiddlewareWithVerifier(
		scores,
		FusionConfigFromConfig(cfg.RiskEngine),
		DecisionConfigFromConfig(cfg.RiskEngine),
		humans,
		nil,
		false,
	)
	return middleware, humans, store
}

func setHighRiskHeaders(request *http.Request) {
	request.Header.Set("X-WAF-Risk-Behavioral", "100")
	request.Header.Set("X-WAF-Risk-TLS", "100")
	request.Header.Set("X-WAF-Risk-Fingerprint", "100")
	request.Header.Set("X-WAF-Risk-Integrity", "100")
	request.Header.Set("X-WAF-Risk-Rate", "100")
	request.Header.Set("X-WAF-Risk-Geo", "100")
}
