package challenge

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
)

func enforcerRequest(action string, accept string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
	request.RemoteAddr = "3.3.3.3:1234"
	request.Header.Set("Accept", accept)
	if action != "" {
		request.Header.Set("X-WAF-Action", action)
	}
	return request
}

// FR-34 / FR-04 : une décision CHALLENGE doit servir la page, pas atteindre
// l'upstream avec un simple en-tête.
func TestEnforcerServesChallengeForChallengeDecision(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	response := httptest.NewRecorder()

	middleware.Enforcer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("a CHALLENGE decision must not reach the upstream")
	})).ServeHTTP(response, enforcerRequest("CHALLENGE", "text/html"))

	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Protected by GaetanDev.fr") {
		t.Fatalf("status = %d, want the challenge page", response.Code)
	}
}

func TestEnforcerPassesOtherDecisions(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	for _, action := range []string{"", "PASS", "OBSERVE", "THROTTLE", "TARPIT"} {
		called := false
		middleware.Enforcer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(httptest.NewRecorder(), enforcerRequest(action, "text/html"))
		if !called {
			t.Fatalf("action %q: next handler should be called", action)
		}
	}
}

// Le visiteur sans clearance est déjà challengé par Handler : la cible de
// l'Enforcer est le porteur d'un cookie valide que le moteur de risque juge de
// nouveau suspect.
func TestEnforcerRechallengesClearanceHolderFlaggedChallenge(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	cookie, err := middleware.cookieIssuer.Issue("3.3.3.3", "example.test", strings.Repeat("a", 64), 75, time.Hour)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	request := enforcerRequest("CHALLENGE", "text/html")
	request.AddCookie(&cookie)
	response := httptest.NewRecorder()

	middleware.Enforcer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("a CHALLENGE decision must not reach the upstream, cookie or not")
	})).ServeHTTP(response, request)

	if !strings.Contains(response.Body.String(), "Protected by GaetanDev.fr") {
		t.Fatalf("status = %d, want the challenge page", response.Code)
	}
}

func TestEnforcerRespectsDisabledDomain(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	middleware.domains.global.Store(false)
	called := false
	middleware.Enforcer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), enforcerRequest("CHALLENGE", "text/html"))

	if !called {
		t.Fatal("challenge_enabled = false must be honoured by the Enforcer too")
	}
}

// Le crédit humain (FR-37) ferme la boucle : le fingerprint du cookie est
// retransmis au moteur de risque, et un succès de verify l'enregistre.
func TestHandlerForwardsClearanceFingerprint(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	fpHash := strings.Repeat("b", 64)
	cookie, err := middleware.cookieIssuer.Issue("3.3.3.3", "example.test", fpHash, 75, time.Hour)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	request := enforcerRequest("", "text/html")
	request.AddCookie(&cookie)

	var forwarded string
	middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Get("X-WAF-Fingerprint-Hash")
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), request)

	if forwarded != fpHash {
		t.Fatalf("X-WAF-Fingerprint-Hash = %q, want the clearance fingerprint %q", forwarded, fpHash)
	}
}

func TestVerifySuccessGrantsHumanCredit(t *testing.T) {
	middleware, store := newTestChallengeMiddleware(t)
	defer store.Close()
	var grantedIP, grantedFP string
	middleware = middleware.WithHumanCredit(func(ip string, _ string, fpHash string) {
		grantedIP, grantedFP = ip, fpHash
	})
	middleware.scores.Set("3.3.3.3", "example.test", 35)
	token, err := middleware.tokenIssuer.GenerateForRedirect("3.3.3.3", "example.test", "/page")
	if err != nil {
		t.Fatalf("GenerateForRedirect() error = %v", err)
	}
	response := httptest.NewRecorder()
	middleware.Handler(http.NotFoundHandler()).ServeHTTP(response, verifyRequest(t, "3.3.3.3:1234", submissionJSON(token, solvePow(t, token, middleware.staticDifficulty()), 1200)))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s, want 200", response.Code, response.Body.String())
	}
	result := response.Result()
	defer func() { _ = result.Body.Close() }()
	payload, err := middleware.cookieIssuer.Validate(result.Cookies()[0].Value, "3.3.3.3", "example.test")
	if err != nil {
		t.Fatalf("issued cookie invalid: %v", err)
	}
	if grantedIP != "3.3.3.3" || grantedFP != payload.FPHash {
		t.Fatalf("human credit = (%q, %q), want (3.3.3.3, %q): the proof must match the cookie fingerprint", grantedIP, grantedFP, payload.FPHash)
	}
}

// Erreur n°2 : un appel API/XHR ne peut pas exécuter le JS — il reste couvert
// par le rate limit et le moteur de risque, comme devant Handler.
func TestEnforcerDoesNotChallengeAPICalls(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	called := false
	middleware.Enforcer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), enforcerRequest("CHALLENGE", "application/json"))

	if !called {
		t.Fatal("API call must not receive the challenge page")
	}
}

// PATCH /waf/admin/config : challenge.enabled s'applique à chaud, à toutes les
// copies du middleware (type valeur).
func TestConfigureTogglesChallengeAtRuntime(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	copyInChain := middleware
	middleware.Configure(config.Challenge{Enabled: false, PowDifficulty: 12})

	called := false
	copyInChain.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), enforcerRequest("", "text/html"))

	if !called {
		t.Fatal("challenge disabled at runtime must no longer serve the page")
	}
	if got := copyInChain.staticDifficulty(); got != 12 {
		t.Fatalf("pow difficulty = %d, want 12", got)
	}
}

// Une page de challenge servie est une action CHALLENGE (logs, métriques,
// stats), pas un PASS.
func TestServedChallengePageAnnouncesChallengeAction(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	response := httptest.NewRecorder()
	middleware.Handler(http.NotFoundHandler()).ServeHTTP(response, enforcerRequest("", "text/html"))

	if got := response.Header().Get("X-WAF-Action"); got != "CHALLENGE" {
		t.Fatalf("X-WAF-Action = %q, want CHALLENGE", got)
	}
}
