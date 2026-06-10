package antibot

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/trust"
)

func TestHeadlessChromeDecrementsScoreAndTriggersChallenge(t *testing.T) {
	middleware, store := newTestMiddleware(t)
	defer store.Close()

	request := requestFrom("1.2.3.4:1234", "/")
	request.Header.Set("User-Agent", "Mozilla/5.0 HeadlessChrome/120.0")
	response := httptest.NewRecorder()

	middleware.Handler(trustAfter(middleware.scores)).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
	visitor := visitorFor(t, store, "1.2.3.4")
	if visitor.Score != 20 {
		t.Fatalf("score = %d, want 20", visitor.Score)
	}
	if got := request.Header.Get("X-WAF-Action"); got != "CHALLENGE" {
		t.Fatalf("X-WAF-Action = %q, want CHALLENGE", got)
	}
	if got := request.Header.Get("X-WAF-Reason"); got != ReasonHeadlessBrowser {
		t.Fatalf("X-WAF-Reason = %q, want %s", got, ReasonHeadlessBrowser)
	}
}

func TestPythonRequestsDecrementsScore(t *testing.T) {
	middleware, store := newTestMiddleware(t)
	defer store.Close()

	request := requestFrom("1.2.3.4:1234", "/")
	request.Header.Set("User-Agent", "python-requests/2.28.0")
	response := httptest.NewRecorder()

	middleware.Handler(trustAfter(middleware.scores)).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
	visitor := visitorFor(t, store, "1.2.3.4")
	if visitor.Score != 35 {
		t.Fatalf("score = %d, want 35", visitor.Score)
	}
}

func TestMissingUserAgentDecrementsScore(t *testing.T) {
	middleware, store := newTestMiddleware(t)
	defer store.Close()

	request := requestFrom("1.2.3.4:1234", "/")
	response := httptest.NewRecorder()

	middleware.Handler(trustAfter(middleware.scores)).ServeHTTP(response, request)

	visitor := visitorFor(t, store, "1.2.3.4")
	if visitor.Score != 30 {
		t.Fatalf("score = %d, want 30", visitor.Score)
	}
}

func TestMissingBrowserHeadersDecrementScore(t *testing.T) {
	middleware, store := newTestMiddleware(t)
	defer store.Close()

	request := requestFrom("1.2.3.4:1234", "/")
	request.Header.Set("User-Agent", "Mozilla/5.0")
	response := httptest.NewRecorder()

	middleware.Handler(trustAfter(middleware.scores)).ServeHTTP(response, request)

	visitor := visitorFor(t, store, "1.2.3.4")
	if visitor.Score != 40 {
		t.Fatalf("score = %d, want 40", visitor.Score)
	}
}

func TestAntibotPublishesFingerprintRiskContribution(t *testing.T) {
	middleware, store := newTestMiddleware(t)
	defer store.Close()

	request := requestFrom("1.2.3.4:1234", "/")
	request.Header.Set("User-Agent", "Mozilla/5.0 HeadlessChrome/120.0")
	response := httptest.NewRecorder()

	middleware.Handler(trustAfter(middleware.scores)).ServeHTTP(response, request)

	// delta -30 (headless) → contribution de risque +30 pour la famille fingerprint.
	if got := request.Header.Get("X-WAF-Risk-fingerprint"); got != "30" {
		t.Fatalf("X-WAF-Risk-fingerprint = %q, want 30", got)
	}
}

func TestHoneypotSetsDeterministicTrigger(t *testing.T) {
	middleware, store := newTestMiddleware(t)
	defer store.Close()

	request := requestFrom("2.3.4.5:1234", "/.env")
	request.Header.Set("User-Agent", "Mozilla/5.0")
	response := httptest.NewRecorder()

	middleware.Handler(trustAfter(middleware.scores)).ServeHTTP(response, request)

	if got := response.Header().Get("X-WAF-Deterministic-Trigger"); got != "honeypot" {
		t.Fatalf("X-WAF-Deterministic-Trigger = %q, want honeypot", got)
	}
}

func TestHoneypotSetsScoreToZeroAndBlocks(t *testing.T) {
	middleware, store := newTestMiddleware(t)
	defer store.Close()
	middleware.scores.Set("2.3.4.5", "example.test", 60)

	request := requestFrom("2.3.4.5:1234", "/.env")
	request.Header.Set("User-Agent", "Mozilla/5.0")
	response := httptest.NewRecorder()

	middleware.Handler(trustAfter(middleware.scores)).ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if got := response.Header().Get("X-WAF-Action"); got != "HONEYPOT" {
		t.Fatalf("X-WAF-Action = %q, want HONEYPOT", got)
	}
	visitor := visitorFor(t, store, "2.3.4.5")
	if visitor.Score != 0 {
		t.Fatalf("score = %d, want 0", visitor.Score)
	}
	if got := response.Header().Get("X-WAF-Reason"); got != ReasonHoneypot {
		t.Fatalf("X-WAF-Reason = %q, want %s", got, ReasonHoneypot)
	}
}

func TestAutomationUserAgentSetsScoreToZeroAndBlocks(t *testing.T) {
	middleware, store := newTestMiddleware(t)
	defer store.Close()

	request := requestFrom("1.2.3.4:1234", "/")
	request.Header.Set("User-Agent", "Selenium")
	response := httptest.NewRecorder()

	middleware.Handler(trustAfter(middleware.scores)).ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	visitor := visitorFor(t, store, "1.2.3.4")
	if visitor.Score != 0 {
		t.Fatalf("score = %d, want 0", visitor.Score)
	}
}

func TestShadowModeObservesHeuristicBlockButHoneypotStillBlocks(t *testing.T) {
	store := memory.New(100)
	defer store.Close()
	cfg := config.Default()
	cfg.Version = "1.0"
	cfg.Server.Listen = ":0"
	cfg.Upstream.Address = "http://example.test"
	cfg.Challenge.Enabled = false
	cfg.Admin.Enabled = false
	manager, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	middleware := New(NewRules(cfg), manager, true) // shadow / calibration
	// En prod avec risk_engine activé, l'aval de l'anti-bot est le moteur de risque
	// (qui observe en shadow), pas un gate de score. On modélise donc un handler
	// terminal neutre pour tester le comportement propre de l'anti-bot.
	passNext := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	// UA d'automation : bloqué en enforcement, observé (laissé passer) en shadow.
	automation := requestFrom("1.2.3.4:1234", "/")
	automation.Header.Set("User-Agent", "Selenium")
	rec := httptest.NewRecorder()
	middleware.Handler(passNext).ServeHTTP(rec, automation)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("shadow mode must not block heuristic automation UA, got 403")
	}

	// Honeypot : reste bloquant même en shadow (déterministe, sans faux positif).
	honeypot := requestFrom("2.3.4.5:1234", "/.env")
	honeypot.Header.Set("User-Agent", "Mozilla/5.0")
	rec2 := httptest.NewRecorder()
	middleware.Handler(passNext).ServeHTTP(rec2, honeypot)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("honeypot must block even in shadow mode, got %d", rec2.Code)
	}
}

func TestWhitelistedActionBypassesAntiBot(t *testing.T) {
	middleware, store := newTestMiddleware(t)
	defer store.Close()

	request := requestFrom("1.2.3.4:1234", "/")
	request.Header.Set("X-WAF-Action", "PASS")
	request.Header.Set("User-Agent", "HeadlessChrome")
	response := httptest.NewRecorder()

	middleware.Handler(trustAfter(middleware.scores)).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
	if _, ok := store.GetVisitor(trust.HashIP("1.2.3.4")); ok {
		t.Fatal("expected no score to be calculated for whitelisted request")
	}
}

func newTestMiddleware(t *testing.T) (Middleware, *memory.Store) {
	t.Helper()

	store := memory.New(100)
	cfg := config.Default()
	cfg.Version = "1.0"
	cfg.Server.Listen = ":0"
	cfg.Upstream.Address = "http://example.test"
	cfg.Challenge.Enabled = false
	cfg.Admin.Enabled = false

	manager, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	return New(NewRules(cfg), manager, false), store
}

func requestFrom(remoteAddr string, path string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://example.test"+path, nil)
	request.RemoteAddr = remoteAddr
	return request
}

func trustAfter(manager *trust.ScoreManager) http.Handler {
	return manager.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
}

func visitorFor(t *testing.T, store *memory.Store, ip string) *storageVisitor {
	t.Helper()
	visitor, ok := store.GetVisitor(trust.HashIP(ip))
	if !ok {
		t.Fatalf("expected visitor for %s", ip)
	}
	return &storageVisitor{Score: visitor.Score}
}

type storageVisitor struct {
	Score int
}
