package antibot

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/middleware/access"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/trust"
)

// Scénarios de specs/features/non-browser-paths.feature (FR-41) portés par la
// couche anti-bot. Le score initial est 50, le seuil de blocage 10.

const captchaHost = "captcha.example.com"

// captchaDomains est le Background de la feature : l'entrée captcha déclare
// /v1/ (préfixe) et /webhook (exact) ; www.example.com n'en déclare aucun.
func captchaDomains() []config.DomainConfig {
	disabled := false
	return []config.DomainConfig{
		{Host: captchaHost, Upstream: "http://10.0.0.1", ChallengeEnabled: &disabled, NonBrowserPaths: []string{"/v1/", "/webhook"}},
		{Host: "www.example.com", Upstream: "http://10.0.0.2"},
	}
}

func TestNonBrowserPathRepeatedServerCallsAreNeverPenalized(t *testing.T) {
	fixture := newNonBrowserFixture(t, captchaDomains())

	for i := range 100 {
		request := apiRequest(http.MethodPost, captchaHost, "/v1/siteverify", "203.0.113.7")
		request.Header.Set("User-Agent", "node")

		response := fixture.serve(request)

		if response.Code != http.StatusNoContent {
			t.Fatalf("request %d: status = %d, want 204 (no anti-bot 403)", i+1, response.Code)
		}
		if got := request.Header.Get(headerRiskFingerprint); got != "" {
			t.Fatalf("request %d: %s = %q, want no fingerprint contribution", i+1, headerRiskFingerprint, got)
		}
	}
	fixture.assertScore(t, "203.0.113.7", 50)
	if got := fixture.exempted[captchaHost]; got != 100 {
		t.Fatalf("exemptions for %s = %d, want 100 (all: %v)", captchaHost, got, fixture.exempted)
	}
}

func TestNonBrowserPathNeutralizesNonBrowserSignals(t *testing.T) {
	cases := []struct {
		name      string
		userAgent string
	}{
		{name: "empty user agent", userAgent: ""},
		{name: "python-requests", userAgent: "python-requests/2.32.0"},
		{name: "curl", userAgent: "curl/8.5.0"},
		{name: "go-http-client", userAgent: "Go-http-client/2.0"},
		{name: "guzzle without accept headers", userAgent: "GuzzleHttp/7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newNonBrowserFixture(t, captchaDomains())
			request := apiRequest(http.MethodPost, captchaHost, "/v1/siteverify", "203.0.113.7")
			request.Header.Set("User-Agent", tc.userAgent)

			response := fixture.serve(request)

			if response.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204 (forwarded upstream)", response.Code)
			}
			fixture.assertScore(t, "203.0.113.7", 50)
			if fixture.exempted[captchaHost] != 1 {
				t.Fatalf("exemptions = %v, want one for %s", fixture.exempted, captchaHost)
			}
		})
	}
}

func TestNonBrowserPathExactPatternAndHostSpelling(t *testing.T) {
	cases := []struct {
		name      string
		host      string
		path      string
		userAgent string
	}{
		{name: "exact pattern", host: captchaHost, path: "/webhook", userAgent: "curl/8.5.0"},
		{name: "prefix itself", host: captchaHost, path: "/v1/", userAgent: "curl/8.5.0"},
		{name: "host case and port", host: "Captcha.Example.com:443", path: "/v1/siteverify", userAgent: "node"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newNonBrowserFixture(t, captchaDomains())
			request := apiRequest(http.MethodPost, tc.host, tc.path, "203.0.113.7")
			request.Header.Set("User-Agent", tc.userAgent)

			fixture.serve(request)

			fixture.assertScore(t, "203.0.113.7", 50)
			if fixture.exempted[captchaHost] != 1 {
				t.Fatalf("exemptions = %v, want one labelled with the configured host %q", fixture.exempted, captchaHost)
			}
		})
	}
}

func TestNonBrowserPathWildcardCoversSubdomainsAndApex(t *testing.T) {
	fixture := newNonBrowserFixture(t, []config.DomainConfig{
		{Host: "*.API.example.com", Upstream: "http://10.0.0.1", NonBrowserPaths: []string{"/v1/"}},
	})

	for _, host := range []string{"eu.api.example.com", "api.example.com"} {
		request := apiRequest(http.MethodPost, host, "/v1/x", "203.0.113.7")
		request.Header.Set("User-Agent", "curl/8.5.0")
		fixture.serve(request)
	}

	fixture.assertScore(t, "203.0.113.7", 50)
	if got := fixture.exempted["*.api.example.com"]; got != 2 {
		t.Fatalf("exemptions = %v, want 2 under the configured wildcard", fixture.exempted)
	}
}

func TestNonBrowserPathOutOfScopeIsStillPenalized(t *testing.T) {
	cases := []struct {
		name string
		host string
		path string
	}{
		{name: "root", host: captchaHost, path: "/"},
		{name: "prefix without its slash", host: captchaHost, path: "/v1"},
		{name: "sibling prefix", host: captchaHost, path: "/v10/x"},
		{name: "case sensitive", host: captchaHost, path: "/V1/siteverify"},
		{name: "exact pattern is not a prefix", host: captchaHost, path: "/webhook/x"},
		{name: "other domain without the key", host: "www.example.com", path: "/v1/siteverify"},
		{name: "undeclared host", host: "evil.test", path: "/v1/siteverify"},
		{name: "parent segment", host: captchaHost, path: "/v1/../admin"},
		{name: "current segment", host: captchaHost, path: "/v1/./siteverify"},
		{name: "double slash", host: captchaHost, path: "/v1//siteverify"},
		{name: "trailing dot segment", host: captchaHost, path: "/v1/."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newNonBrowserFixture(t, captchaDomains())
			request := apiRequest(http.MethodGet, tc.host, tc.path, "203.0.113.7")
			request.Header.Set("User-Agent", "curl/8.5.0")

			fixture.serve(request)

			fixture.assertScore(t, "203.0.113.7", 35)
			if len(fixture.exempted) != 0 {
				t.Fatalf("exemptions = %v, want none", fixture.exempted)
			}
		})
	}
}

// Pas d'héritage : une entrée exacte sans la clé ne prend pas la liste d'un
// wildcard placé après, qui reste appliqué aux hôtes qu'il est seul à couvrir.
func TestNonBrowserPathFirstMatchingEntryWinsWithoutInheritance(t *testing.T) {
	fixture := newNonBrowserFixture(t, []config.DomainConfig{
		{Host: "api.example.com", Upstream: "http://10.0.0.1"},
		{Host: "*.example.com", Upstream: "http://10.0.0.2", NonBrowserPaths: []string{"/v1/"}},
	})

	inherited := apiRequest(http.MethodPost, "api.example.com", "/v1/x", "203.0.113.7")
	inherited.Header.Set("User-Agent", "curl/8.5.0")
	fixture.serve(inherited)
	fixture.assertScore(t, "203.0.113.7", 35)

	covered := apiRequest(http.MethodPost, "other.example.com", "/v1/x", "203.0.113.8")
	covered.Header.Set("User-Agent", "curl/8.5.0")
	fixture.serve(covered)
	fixture.assertScore(t, "203.0.113.8", 50)
}

func TestNonBrowserPathWithoutTheKeyKeepsCurrentBehavior(t *testing.T) {
	fixture := newNonBrowserFixture(t, nil)
	request := apiRequest(http.MethodPost, captchaHost, "/v1/siteverify", "203.0.113.7")
	request.Header.Set("User-Agent", "curl/8.5.0")

	fixture.serve(request)

	fixture.assertScore(t, "203.0.113.7", 35)
}

// Honeypot, UA d'automatisation et navigateur headless ne sont pas des
// signaux « non navigateur » : ils restent évalués sous un chemin exempté.
func TestNonBrowserPathKeepsDeterministicAndHeadlessSignals(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		userAgent  string
		wantCode   int
		wantReason string
		wantScore  int
	}{
		{name: "honeypot", path: "/v1/.env", userAgent: "node", wantCode: http.StatusForbidden, wantReason: ReasonHoneypot, wantScore: 0},
		{name: "automation", path: "/v1/siteverify", userAgent: "Mozilla/5.0 puppeteer", wantCode: http.StatusForbidden, wantReason: ReasonAutomationUA, wantScore: 0},
		{name: "headless", path: "/v1/siteverify", userAgent: "HeadlessChrome/120.0", wantCode: http.StatusNoContent, wantReason: ReasonHeadlessBrowser, wantScore: 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newNonBrowserFixture(t, captchaDomains(), "/v1/.env")
			request := apiRequest(http.MethodPost, captchaHost, tc.path, "203.0.113.9")
			request.Header.Set("User-Agent", tc.userAgent)

			response := fixture.serve(request)

			if response.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", response.Code, tc.wantCode)
			}
			if got := request.Header.Get("X-WAF-Reason"); got != tc.wantReason {
				t.Fatalf("X-WAF-Reason = %q, want %q", got, tc.wantReason)
			}
			fixture.assertScore(t, "203.0.113.9", tc.wantScore)
			if len(fixture.exempted) != 0 {
				t.Fatalf("exemptions = %v, want none", fixture.exempted)
			}
		})
	}
}

// Un visiteur banni (honeypot) ou déjà BLOCKED le reste sur un chemin exempté :
// l'exemption n'efface que la pénalité de la requête, pas l'état acquis.
func TestNonBrowserPathKeepsBlockedVisitorsBlocked(t *testing.T) {
	cases := []struct {
		name  string
		block func(*trust.ScoreManager)
	}{
		{name: "honeypot ban", block: func(m *trust.ScoreManager) { m.BanHoneypot("203.0.113.9", captchaHost) }},
		{name: "score at zero", block: func(m *trust.ScoreManager) { m.Set("203.0.113.9", captchaHost, 0) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newNonBrowserFixture(t, captchaDomains())
			tc.block(fixture.scores)
			request := apiRequest(http.MethodPost, captchaHost, "/v1/siteverify", "203.0.113.9")
			request.Header.Set("User-Agent", "node")

			response := fixture.serve(request)

			if response.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 for an already blocked visitor", response.Code)
			}
		})
	}
}

// L'exemption FR-41 étend les signaux levés à missing_user_agent ; celle de
// whitelist_user_agents n'en hérite pas.
func TestWhitelistedUserAgentExemptionDoesNotCoverMissingUserAgent(t *testing.T) {
	fixture := newNonBrowserFixture(t, captchaDomains())
	request := apiRequest(http.MethodGet, captchaHost, "/", "203.0.113.7")
	request.Header.Set(access.HeaderUserAgentWhitelisted, "true")

	fixture.serve(request)

	fixture.assertScore(t, "203.0.113.7", 30)
}

// Sans compteur branché (WithNonBrowserExemptCounter non appelé), l'exemption
// s'applique quand même.
func TestNonBrowserPathExemptsWithoutACounter(t *testing.T) {
	store := memory.New(100)
	t.Cleanup(store.Close)
	cfg := nonBrowserConfig(captchaDomains())
	manager, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	request := apiRequest(http.MethodPost, captchaHost, "/v1/siteverify", "203.0.113.7")
	request.Header.Set("User-Agent", "node")

	New(NewRules(cfg), manager, false).Handler(trustAfter(manager)).ServeHTTP(httptest.NewRecorder(), request)

	if score := manager.Peek("203.0.113.7", captchaHost).Score; score != 50 {
		t.Fatalf("score = %d, want 50", score)
	}
}

type nonBrowserFixture struct {
	handler  http.Handler
	scores   *trust.ScoreManager
	exempted map[string]int
}

func newNonBrowserFixture(t *testing.T, domains []config.DomainConfig, honeypotPaths ...string) *nonBrowserFixture {
	t.Helper()
	store := memory.New(100)
	t.Cleanup(store.Close)
	cfg := nonBrowserConfig(domains)
	if len(honeypotPaths) > 0 {
		cfg.HoneypotPaths = honeypotPaths
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	manager, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	fixture := &nonBrowserFixture{scores: manager, exempted: map[string]int{}}
	middleware := New(NewRules(cfg), manager, false).WithNonBrowserExemptCounter(func(domain string) {
		fixture.exempted[domain]++
	})
	fixture.handler = middleware.Handler(trustAfter(manager))
	return fixture
}

func nonBrowserConfig(domains []config.DomainConfig) config.Config {
	cfg := config.Default()
	cfg.Version = "1.0"
	cfg.Server.Listen = ":0"
	cfg.Upstream.Address = "http://example.test"
	cfg.Challenge.Enabled = false
	cfg.Admin.Enabled = false
	cfg.Domains = domains
	return cfg
}

func (f *nonBrowserFixture) serve(request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	f.handler.ServeHTTP(response, request)
	return response
}

func (f *nonBrowserFixture) assertScore(t *testing.T, ip string, want int) {
	t.Helper()
	if got := f.scores.Peek(ip, captchaHost).Score; got != want {
		t.Fatalf("score of %s = %d, want %d", ip, got, want)
	}
}

// apiRequest est un appel serveur à serveur : ni Accept-Language ni
// Accept-Encoding, User-Agent à poser par l'appelant.
func apiRequest(method, host, path, ip string) *http.Request {
	request := httptest.NewRequest(method, "http://"+captchaHost+"/", nil)
	request.Host = host
	request.URL.Path = path
	request.RemoteAddr = ip + ":1234"
	return request
}
