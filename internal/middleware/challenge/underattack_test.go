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

// whitelistedCrawlerRequest simule un User-Agent de whitelist_user_agents
// (marqué en amont par le middleware access).
func whitelistedCrawlerRequest(underAttack bool) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://status.test/", nil)
	request.RemoteAddr = "9.9.9.9:1234"
	request.Header.Set("Accept", "text/html")
	request.Header.Set("User-Agent", "Twitterbot/1.0")
	request.Header.Set("X-WAF-UA-Whitelisted", "true")
	if underAttack {
		request.Header.Set("X-WAF-Under-Attack-Enforce", "true")
	}
	return request
}

// Sous attaque (FR-39), un User-Agent whitelisté n'est pas une clearance : seul
// un crawler vérifié par reverse-DNS passe sans challenge. Hors attaque,
// l'exemption tient, sauf pour un crawler démasqué.
func TestWhitelistedUserAgentExemption(t *testing.T) {
	base, _ := newTestChallengeMiddleware(t)
	cases := []struct {
		name        string
		check       func(string, string) (bool, bool)
		underAttack bool
		challenged  bool
	}{
		{"no verifier, normal", nil, false, false},
		{"no verifier, under attack", nil, true, true},
		{"unverifiable UA, normal", func(string, string) (bool, bool) { return false, false }, false, false},
		{"unverifiable UA, under attack", func(string, string) (bool, bool) { return false, false }, true, true},
		{"verified crawler, under attack", func(string, string) (bool, bool) { return true, false }, true, false},
		{"spoofed crawler, normal", func(string, string) (bool, bool) { return false, true }, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			middleware := base
			if tc.check != nil {
				middleware = base.WithCrawlerCheck(tc.check)
			}
			if got := servedChallenge(t, middleware, whitelistedCrawlerRequest(tc.underAttack)); got != tc.challenged {
				t.Fatalf("challenged = %v, want %v", got, tc.challenged)
			}
		})
	}
}

// FR-39 : sous attaque, une requête non-navigateur sans clearance n'est pas
// challengée mais marquée pour le plafond THROTTLE du rate limit ; hors
// attaque, elle ne l'est pas.
func TestUnderAttackMarksNonBrowserRequestsForThrottle(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	for _, underAttack := range []bool{false, true} {
		for _, request := range []*http.Request{
			httptest.NewRequest(http.MethodPost, "http://api.test/v1/orders", nil),
			httptest.NewRequest(http.MethodGet, "http://api.test/v1/users", nil),
		} {
			request.RemoteAddr = "9.9.9.9:1234"
			request.Header.Set("Accept", "application/json")
			if underAttack {
				request.Header.Set("X-WAF-Under-Attack-Enforce", "true")
			}
			var marked string
			middleware.Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				marked = r.Header.Get("X-WAF-Under-Attack-Throttle")
			})).ServeHTTP(httptest.NewRecorder(), request)
			if want := map[bool]string{false: "", true: "true"}[underAttack]; marked != want {
				t.Fatalf("%s under_attack=%v: throttle mark = %q, want %q", request.Method, underAttack, marked, want)
			}
		}
	}
}

// Avec antiddos.under_attack.challenge_non_browser, un simple en-tête Accept
// ne soustrait plus une requête au challenge forcé.
func TestUnderAttackChallengesNonBrowserWhenConfigured(t *testing.T) {
	middleware, _ := newTestChallengeMiddleware(t)
	middleware.challengeNonBrowser = true
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		request := httptest.NewRequest(method, "http://status.test/", nil)
		request.RemoteAddr = "9.9.9.9:1234"
		request.Header.Set("Accept", "application/json")
		if servedChallenge(t, middleware, cloneReq(request)) {
			t.Fatalf("%s: outside under attack mode, a JSON client is not challenged", method)
		}
		request.Header.Set("X-WAF-Under-Attack-Enforce", "true")
		if !servedChallenge(t, middleware, request) {
			t.Fatalf("%s: under attack with challenge_non_browser, the request must be challenged", method)
		}
	}
}
