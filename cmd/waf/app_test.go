package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
)

// cloudflareEdge est une adresse des plages Cloudflare compilées : les CF-*
// d'une requête qui en vient sont honorés (ADR-019).
const cloudflareEdge = "173.245.48.1:443"

// testAppConfig rend une configuration par défaut valide qui proxifie vers
// upstreamURL, sans API admin ni écriture du journal hors du test.
func testAppConfig(upstreamURL string) config.Config {
	cfg := config.Default()
	cfg.Version = "1.0"
	cfg.Server.Listen = ":0"
	cfg.Upstream.Address = upstreamURL
	cfg.Challenge.SecretKey = "0123456789abcdef0123456789abcdef"
	cfg.Admin.Enabled = false
	cfg.Logging.Level = "error"
	return cfg
}

// upstreamRecorder est une origine de test : elle répond 204 et retient les
// en-têtes de la dernière requête reçue.
type upstreamRecorder struct {
	server *httptest.Server
	hits   chan http.Header
}

func newUpstreamRecorder(t *testing.T) *upstreamRecorder {
	t.Helper()
	recorder := &upstreamRecorder{hits: make(chan http.Header, 1024)}
	recorder.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.hits <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(recorder.server.Close)
	return recorder
}

// newTestApp construit l'application réelle (build puis routes), comme run le
// fait avant d'écouter : la racine de composition n'était couverte par aucun
// test, alors que tout le câblage s'y trouve.
func newTestApp(t *testing.T, cfg config.Config) http.Handler {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	a := &app{cfg: &cfg, startedAt: time.Now()}
	t.Cleanup(a.stop.run)
	if err := a.build(); err != nil {
		t.Fatalf("build() error = %v", err)
	}
	return a.routes()
}

// edgeRequest simule une requête de navigateur relayée par Cloudflare.
func edgeRequest(method string, target string, clientIP string) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	request.RemoteAddr = cloudflareEdge
	request.Header.Set("CF-Connecting-IP", clientIP)
	request.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15")
	request.Header.Set("Accept-Language", "fr-FR")
	request.Header.Set("Accept-Encoding", "gzip")
	return request
}

func serve(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func isChallengePage(response *httptest.ResponseRecorder) bool {
	return response.Header().Get("X-WAF-Action") == "CHALLENGE" && strings.Contains(response.Body.String(), "Protected by GaetanDev.fr")
}

// L'application par défaut sert le health, challenge une navigation et
// proxifie un asset.
func TestAppServesDefaultPipeline(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	handler := newTestApp(t, testAppConfig(upstream.server.URL))

	if response := serve(handler, httptest.NewRequest(http.MethodGet, "http://example.test/waf/health", nil)); response.Code != http.StatusOK {
		t.Fatalf("GET /waf/health: status = %d, want 200", response.Code)
	}
	page := edgeRequest(http.MethodGet, "http://example.test/", "198.51.100.7")
	page.Header.Set("Accept", "text/html")
	if response := serve(handler, page); !isChallengePage(response) {
		t.Fatalf("GET / (navigation): status = %d, want the challenge page", response.Code)
	}
	if response := serve(handler, edgeRequest(http.MethodGet, "http://example.test/app.js", "198.51.100.7")); response.Code != http.StatusNoContent {
		t.Fatalf("GET /app.js: status = %d, want 204 (proxied)", response.Code)
	}
}

// FR-24 : un pays bloqué l'est aussi sur un chemin d'asset — PASS static_asset
// le laissait atteindre l'origine.
func TestAppGeoBlocksStaticAssets(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	cfg := testAppConfig(upstream.server.URL)
	cfg.Geo.Enabled = true
	cfg.Geo.BlockedCountries = []string{"XX"}
	handler := newTestApp(t, cfg)

	for _, target := range []string{"/page", "/index.php/x.js?id=1", "/favicon.ico?cb=123"} {
		request := edgeRequest(http.MethodGet, "http://example.test"+target, "198.51.100.8")
		request.Header.Set("CF-IPCountry", "XX")
		if response := serve(handler, request); response.Code != http.StatusForbidden {
			t.Errorf("GET %s from a blocked country: status = %d, want 403", target, response.Code)
		}
	}
	if len(upstream.hits) != 0 {
		t.Fatalf("upstream reached %d times, want 0", len(upstream.hits))
	}
}

// FR-24 / FR-39 : un flood distribué d'assets (« GET /x.js?r=<aléa> ») est
// compté dans la pression du domaine et, sous attaque, challengé sans clearance.
func TestAppChallengesAssetFloodUnderAttack(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	cfg := testAppConfig(upstream.server.URL)
	cfg.AntiDDoS.GlobalRequestsPerSecond = 5
	handler := newTestApp(t, cfg)

	var last *httptest.ResponseRecorder
	for i := range 40 {
		request := edgeRequest(http.MethodGet, "http://status.example.test/x.js?r="+strconv.Itoa(i), "198.51.100."+strconv.Itoa(10+i))
		request.Header.Set("Accept", "*/*")
		last = serve(handler, request)
	}
	if !isChallengePage(last) {
		t.Fatalf("asset flood under attack: status = %d, action = %q, want the challenge page", last.Code, last.Header().Get("X-WAF-Action"))
	}
}

// FR-07 : le honeypot bannit le visiteur sur toutes ses requêtes suivantes,
// moteur de risque actif (appliqué ou en shadow) : le score remis à 0 ne
// bloquait que via le trust score, absent avec le moteur.
func TestAppHoneypotBanOutlivesTheTrapRequest(t *testing.T) {
	for _, shadow := range []bool{false, true} {
		upstream := newUpstreamRecorder(t)
		cfg := testAppConfig(upstream.server.URL)
		cfg.RiskEngine.ShadowMode = shadow
		handler := newTestApp(t, cfg)

		trap := serve(handler, edgeRequest(http.MethodGet, "http://example.test/.env", "198.51.100.20"))
		if trap.Code != http.StatusForbidden || trap.Header().Get("X-WAF-Action") != "HONEYPOT" {
			t.Fatalf("shadow=%v GET /.env: status = %d, action = %q; want 403 HONEYPOT", shadow, trap.Code, trap.Header().Get("X-WAF-Action"))
		}
		for _, target := range []string{"/", "/page", "/app.js", "/waf/verify"} {
			request := edgeRequest(http.MethodGet, "http://example.test"+target, "198.51.100.20")
			request.Header.Set("Accept", "text/html")
			response := serve(handler, request)
			if response.Code != http.StatusForbidden || response.Header().Get("X-WAF-Reason") != "honeypot_ban" {
				t.Errorf("shadow=%v GET %s after the trap: status = %d, reason = %q; want 403 honeypot_ban", shadow, target, response.Code, response.Header().Get("X-WAF-Reason"))
			}
		}
		if len(upstream.hits) != 0 {
			t.Fatalf("shadow=%v: upstream reached %d times, want 0", shadow, len(upstream.hits))
		}
	}
}

// FR-07 : sans moteur de risque, shadow_mode (true par défaut) ne désactive
// pas les blocages heuristiques de l'anti-bot.
func TestAppAntiBotBlocksWithoutRiskEngine(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	cfg := testAppConfig(upstream.server.URL)
	cfg.RiskEngine.Enabled = false
	handler := newTestApp(t, cfg)

	request := edgeRequest(http.MethodGet, "http://example.test/", "198.51.100.21")
	request.Header.Set("User-Agent", "Mozilla/5.0 Selenium")
	if response := serve(handler, request); response.Code != http.StatusForbidden {
		t.Fatalf("automation UA without risk engine: status = %d, want 403", response.Code)
	}
}

// FR-01 : l'upstream reçoit l'IP réelle du client et le schéma qu'il voit,
// et non ceux de la connexion du point de présence Cloudflare.
func TestAppForwardsClientIPAndScheme(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	cfg := testAppConfig(upstream.server.URL)
	cfg.Challenge.Enabled = false
	handler := newTestApp(t, cfg)

	request := edgeRequest(http.MethodGet, "http://example.test/page", "198.51.100.30")
	request.Header.Set("CF-Visitor", `{"scheme":"https"}`)
	request.Header.Set("X-Forwarded-For", "203.0.113.66")
	if response := serve(handler, request); response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
	forwarded := <-upstream.hits
	if got := forwarded.Get("X-Forwarded-For"); got != "198.51.100.30" {
		t.Errorf("X-Forwarded-For = %q, want the client IP 198.51.100.30", got)
	}
	if got := forwarded.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want https", got)
	}

	direct := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
	direct.RemoteAddr = "198.51.100.31:5555"
	direct.Header.Set("CF-Visitor", `{"scheme":"https"}`)
	direct.Header.Set("User-Agent", "Mozilla/5.0 Safari/605.1.15")
	direct.Header.Set("Accept-Language", "fr")
	direct.Header.Set("Accept-Encoding", "gzip")
	if response := serve(handler, direct); response.Code != http.StatusNoContent {
		t.Fatalf("direct request: status = %d, want 204", response.Code)
	}
	forwarded = <-upstream.hits
	if got := forwarded.Get("X-Forwarded-Proto"); got != "http" {
		t.Errorf("forged CF-Visitor outside Cloudflare: X-Forwarded-Proto = %q, want http", got)
	}
	if got := forwarded.Get("X-Forwarded-For"); got != "198.51.100.31" {
		t.Errorf("direct request: X-Forwarded-For = %q, want 198.51.100.31", got)
	}
}

// La racine de composition câble chaque composant optionnel : pool
// d'upstreams, threat intel, règles, géo, alerting, API admin, protection
// d'origine. Une requête propre est servie par le pool avec le token
// d'origine, une règle custom bloque.
func TestAppBuildsEveryOptionalComponent(t *testing.T) {
	upstream := newUpstreamRecorder(t)
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(webhook.Close)
	rulesFile := filepath.Join(t.TempDir(), "rules.yaml")
	rules := "rules:\n  - name: block-admin-probe\n    enabled: true\n    conditions:\n      - field: path\n        operator: equals\n        value: /wp-login-probe\n    actions:\n      - type: block\n"
	if err := os.WriteFile(rulesFile, []byte(rules), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	cfg := testAppConfig("http://127.0.0.1:1")
	cfg.Challenge.Enabled = false
	cfg.UpstreamPool.Enabled = true
	cfg.UpstreamPool.Upstreams = []config.PoolUpstream{{Address: upstream.server.URL}}
	cfg.ThreatIntel.Enabled = true
	cfg.ThreatIntel.BlocklistCIDRs = []string{"203.0.113.0/24"}
	cfg.Rules.Enabled = true
	cfg.Rules.File = rulesFile
	cfg.Geo.Enabled = true
	cfg.Geo.BlockedCountries = []string{"XX"}
	cfg.Alerting.Enabled = true
	cfg.Alerting.Webhooks = []config.AlertWebhook{{Type: "discord", URL: webhook.URL}}
	cfg.Admin.Enabled = true
	cfg.Admin.Token = strings.Repeat("a", 32)
	cfg.OriginProtection.Enabled = true
	cfg.OriginProtection.Secret = strings.Repeat("o", 32)
	handler := newTestApp(t, cfg)

	if response := serve(handler, edgeRequest(http.MethodGet, "http://example.test/page", "198.51.100.40")); response.Code != http.StatusNoContent {
		t.Fatalf("clean request through the pool: status = %d, want 204", response.Code)
	}
	forwarded := <-upstream.hits
	if forwarded.Get("X-Waf-Origin-Token") == "" {
		t.Fatal("origin protection: the upstream received no X-WAF-Origin-Token")
	}
	if response := serve(handler, edgeRequest(http.MethodGet, "http://example.test/wp-login-probe", "198.51.100.41")); response.Code != http.StatusForbidden {
		t.Fatalf("custom rule: status = %d, want 403", response.Code)
	}
}
