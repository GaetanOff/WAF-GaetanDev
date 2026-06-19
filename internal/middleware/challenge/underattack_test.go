package challenge

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// servedChallenge exécute le middleware et indique si la page de challenge a été
// servie (vs. requête transmise à next).
func servedChallenge(t *testing.T, m Middleware, r *http.Request) bool {
	t.Helper()
	response := httptest.NewRecorder()
	passed := false
	m.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		passed = true
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(response, r)
	if passed {
		return false
	}
	return strings.Contains(response.Body.String(), "Protected by GaetanDev.fr")
}

// TestUnderAttackForcesChallengeOnRawGet : sous attaque (FR-39), un GET sans cookie
// qui n'envoie pas "Accept: text/html" (flood brut) est tout de même challengé,
// alors qu'en temps normal il passerait outre.
func TestUnderAttackForcesChallengeOnRawGet(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)

	for _, accept := range []string{"", "*/*"} {
		request := httptest.NewRequest(http.MethodGet, "http://status.test/", nil)
		request.RemoteAddr = "9.9.9.9:1234"
		if accept != "" {
			request.Header.Set("Accept", accept)
		}

		// Sans le mode sous attaque : passe outre (non-navigation).
		if servedChallenge(t, middleware, cloneReq(request)) {
			t.Fatalf("Accept=%q: hors attaque, un GET brut ne doit pas être challengé", accept)
		}

		// Sous attaque (enforce) : challengé.
		under := cloneReq(request)
		under.Header.Set("X-WAF-Under-Attack-Enforce", "true")
		if !servedChallenge(t, middleware, under) {
			t.Fatalf("Accept=%q: sous attaque, un GET brut doit être challengé", accept)
		}
	}
}

// TestUnderAttackExemptsJSONClients : même sous attaque, un client négociant
// explicitement application/json (API/XHR) ne reçoit pas de challenge JS insoluble.
func TestUnderAttackExemptsJSONClients(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	request := httptest.NewRequest(http.MethodGet, "http://api.test/v1/users", nil)
	request.RemoteAddr = "9.9.9.9:1234"
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-WAF-Under-Attack-Enforce", "true")

	if servedChallenge(t, middleware, request) {
		t.Fatal("un client API JSON ne doit jamais recevoir la page de challenge")
	}
}

// TestUnderAttackHonorsValidCookie : un visiteur avec clearance (cookie valide)
// passe sans friction, même sous attaque.
func TestUnderAttackHonorsValidCookie(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	cookie, err := middleware.cookieIssuer.Issue("9.9.9.9", "status.test", strings.Repeat("a", 64), 75, time.Hour)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://status.test/", nil)
	request.RemoteAddr = "9.9.9.9:1234"
	request.Header.Set("Accept", "text/html")
	request.Header.Set("X-WAF-Under-Attack-Enforce", "true")
	request.AddCookie(&cookie)

	if servedChallenge(t, middleware, request) {
		t.Fatal("un cookie valide doit passer sans friction même sous attaque")
	}
}

// TestUnderAttackDoesNotChallengeNonGet : une méthode non GET/HEAD n'est pas
// challengée (un POST ne peut pas rejouer un challenge JS de navigation).
func TestUnderAttackDoesNotChallengeNonGet(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	request := httptest.NewRequest(http.MethodPost, "http://status.test/submit", nil)
	request.RemoteAddr = "9.9.9.9:1234"
	request.Header.Set("X-WAF-Under-Attack-Enforce", "true")

	if servedChallenge(t, middleware, request) {
		t.Fatal("une requête POST ne doit pas être challengée sous attaque")
	}
}

func cloneReq(r *http.Request) *http.Request {
	clone := r.Clone(r.Context())
	return clone
}
