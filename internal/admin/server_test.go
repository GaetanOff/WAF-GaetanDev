package admin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/middleware/access"
	"github.com/gaetandev/waf/internal/storage"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/trust"
)

const testAdminToken = "0123456789abcdef0123456789abcdef"

func TestAdminRejectsMissingBearerToken(t *testing.T) {
	server := newTestServer(t)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://admin.test/waf/admin/blacklist", nil))

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
}

func TestAdminBlacklistCRUDUpdatesAccessRules(t *testing.T) {
	server := newTestServer(t)
	handler := server.Handler()

	create := requestWithAuth(http.MethodPost, "/waf/admin/blacklist", `{"ip":"1.2.3.4","reason":"scanner"}`)
	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, create)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s, want 201", createResponse.Code, createResponse.Body.String())
	}
	if ok, reason := server.accessRules.IsBlacklisted("1.2.3.4"); !ok || reason != "blacklist_exact" {
		t.Fatalf("blacklist active=%v reason=%q, want blacklist_exact", ok, reason)
	}

	listRecorder := httptest.NewRecorder()
	handler.ServeHTTP(listRecorder, requestWithAuth(http.MethodGet, "/waf/admin/blacklist", ""))
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200", listRecorder.Code)
	}
	var entries listResponse[IPEntry]
	if err := json.NewDecoder(listRecorder.Body).Decode(&entries); err != nil {
		t.Fatalf("decode blacklist: %v", err)
	}
	if entries.Total != 1 || entries.Items[0].IP != "1.2.3.4" {
		t.Fatalf("blacklist list = %+v, want one 1.2.3.4", entries)
	}

	deleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteResponse, requestWithAuth(http.MethodDelete, "/waf/admin/blacklist/1.2.3.4", ""))
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", deleteResponse.Code)
	}
	if ok, _ := server.accessRules.IsBlacklisted("1.2.3.4"); ok {
		t.Fatal("blacklist entry should be inactive after delete")
	}
}

func TestAdminWhitelistCRUDUpdatesAccessRules(t *testing.T) {
	server := newTestServer(t)
	handler := server.Handler()

	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, requestWithAuth(http.MethodPost, "/waf/admin/whitelist", `{"ip":"192.168.0.0/24"}`))
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s, want 201", createResponse.Code, createResponse.Body.String())
	}
	if ok, reason := server.accessRules.IsWhitelisted("192.168.0.10"); !ok || reason != "whitelist_cidr" {
		t.Fatalf("whitelist active=%v reason=%q, want whitelist_cidr", ok, reason)
	}

	deleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteResponse, requestWithAuth(http.MethodDelete, "/waf/admin/whitelist/192.168.0.0%2F24", ""))
	if deleteResponse.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", deleteResponse.Code)
	}
	if ok, _ := server.accessRules.IsWhitelisted("192.168.0.10"); ok {
		t.Fatal("whitelist entry should be inactive after delete")
	}
}

func TestAdminVisitorsAndStats(t *testing.T) {
	server := newTestServer(t)
	visitor := server.scores.Set("1.2.3.4", "example.test", 75)

	visitorResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(visitorResponse, requestWithAuth(http.MethodGet, "/waf/admin/visitors/"+visitor.IPHash, ""))
	if visitorResponse.Code != http.StatusOK {
		t.Fatalf("visitor status = %d, want 200", visitorResponse.Code)
	}

	statsResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(statsResponse, requestWithAuth(http.MethodGet, "/waf/stats", ""))
	if statsResponse.Code != http.StatusOK {
		t.Fatalf("stats status = %d, want 200", statsResponse.Code)
	}
}

func TestAdminConfigMasksSecrets(t *testing.T) {
	server := newTestServer(t)
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, requestWithAuth(http.MethodGet, "/waf/admin/config", ""))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if bytes.Contains(response.Body.Bytes(), []byte(testAdminToken)) {
		t.Fatalf("config response leaked admin token: %s", response.Body.String())
	}
	if !bytes.Contains(response.Body.Bytes(), []byte(`"Token":"***"`)) {
		t.Fatalf("config response did not mask admin token: %s", response.Body.String())
	}
}

// Le secret HMAC de l'origine (FR-19), la clé AbuseIPDB, le mot de passe Redis
// et les URL de webhook (qui portent leur jeton) sont masqués comme les autres.
func TestAdminConfigMasksEverySecret(t *testing.T) {
	secrets := []string{"origin-hmac-secret-value", "abuseipdb-api-key-value", "redis-password-value", "https://hooks.slack.test/T000/B000/webhook-token"}
	server := newTestServerWith(t, func(cfg *config.Config) {
		cfg.OriginProtection.Secret = secrets[0]
		cfg.ThreatIntel.AbuseIPDB.APIKey = secrets[1]
		cfg.Storage.Redis = &config.RedisConfig{Address: "127.0.0.1:6379", Password: secrets[2]}
		cfg.Alerting.Webhooks = []config.AlertWebhook{{Type: "slack", URL: secrets[3]}}
	})
	response := httptest.NewRecorder()

	server.Handler().ServeHTTP(response, requestWithAuth(http.MethodGet, "/waf/admin/config", ""))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	for _, secret := range secrets {
		if bytes.Contains(response.Body.Bytes(), []byte(secret)) {
			t.Errorf("config response leaked %q", secret)
		}
	}
}

// Masquer ne doit pas modifier la configuration active : Storage.Redis et
// Alerting.Webhooks sont partagés avec elle par la copie de Config.
func TestSanitizedConfigLeavesTheActiveConfigIntact(t *testing.T) {
	var cfg config.Config
	cfg.Storage.Redis = &config.RedisConfig{Password: "redis-password"}
	cfg.Alerting.Webhooks = []config.AlertWebhook{{URL: "https://hooks.test/token"}}

	masked := sanitizedConfig(cfg)

	if masked.Storage.Redis.Password != maskedSecret || masked.Alerting.Webhooks[0].URL != maskedSecret {
		t.Fatalf("masked = %+v / %+v, want secrets replaced by %q", *masked.Storage.Redis, masked.Alerting.Webhooks, maskedSecret)
	}
	if cfg.Storage.Redis.Password != "redis-password" || cfg.Alerting.Webhooks[0].URL != "https://hooks.test/token" {
		t.Fatalf("active config was modified: %+v / %+v", *cfg.Storage.Redis, cfg.Alerting.Webhooks)
	}
}

// FR-23 — vérifie que server.max_header_value_count est bien transmis au
// http.Server (Go 1.27+) et que la requête est rejetée AVANT d'atteindre le
// handler : une requête sous la limite passe (401, faute de token), une requête
// au-dessus n'obtient pas de réponse applicative.
func TestAdminServerEnforcesMaxHeaderValueCount(t *testing.T) {
	const limit = 20

	server := newTestServerWith(t, func(cfg *config.Config) {
		cfg.Server.MaxHeaderValueCount = limit
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() { _ = server.httpServer.Serve(listener) }()

	url := fmt.Sprintf("http://%s/waf/admin/blacklist", listener.Addr().String())

	// Sous la limite : la requête atteint le routeur admin.
	status, err := statusWithHeaderLines(t, url, limit/2)
	if err != nil {
		t.Fatalf("request under the limit failed: %v", err)
	}
	if status != http.StatusUnauthorized {
		t.Fatalf("status under the limit = %d, want 401", status)
	}

	// Au-dessus : le serveur coupe au parsing, aucune réponse applicative.
	status, err = statusWithHeaderLines(t, url, limit*4)
	if err == nil && status == http.StatusUnauthorized {
		t.Fatal("request above max_header_value_count reached the handler")
	}
}

// statusWithHeaderLines envoie une requête portant `count` lignes d'en-tête
// distinctes (chacune compte pour une valeur, contrairement aux valeurs
// séparées par des virgules sur une seule ligne) et renvoie le code de statut.
//
// Le corps est fermé ici : le test ne s'intéresse qu'au statut, et renvoyer la
// *http.Response obligerait chaque appelant à le fermer.
func statusWithHeaderLines(t *testing.T, url string, count int) (int, error) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	for i := range count {
		request.Header.Add(fmt.Sprintf("X-Filler-%d", i), "x")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer func() { _ = response.Body.Close() }()
	return response.StatusCode, nil
}

// admin.openapi.yaml, getHealth : status vaut "degraded" quand le stockage
// partagé est en mode dégradé (ADR-021), "ok" sinon ; version est requise.
func TestHealthReportsDegradedStorage(t *testing.T) {
	for _, tc := range []struct {
		degraded bool
		want     string
	}{{false, "ok"}, {true, "degraded"}} {
		server := newTestServer(t)
		server.store = reportingStore{Store: server.store, degraded: tc.degraded}
		response := httptest.NewRecorder()

		server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://admin.test/waf/health", nil))

		var body struct {
			Status  string `json:"status"`
			Version string `json:"version"`
		}
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatalf("decode health: %v", err)
		}
		if response.Code != http.StatusOK || body.Status != tc.want || body.Version == "" {
			t.Fatalf("degraded=%v: status %d body %+v, want 200 status=%s with a version", tc.degraded, response.Code, body, tc.want)
		}
	}
}

type reportingStore struct {
	storage.Store
	degraded bool
}

func (s reportingStore) Degraded() bool { return s.degraded }

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return newTestServerWith(t, nil)
}

// newTestServerWith construit un serveur admin de test ; customize (optionnel)
// permet d'ajuster la config AVANT NewServer, donc de tester le câblage
// config -> http.Server.
func newTestServerWith(t *testing.T, customize func(*config.Config)) *Server {
	t.Helper()
	cfg := config.Default()
	cfg.Version = "1.0"
	cfg.Server.Listen = ":0"
	cfg.Server.AdminListen = "127.0.0.1:0"
	cfg.Upstream.Address = "http://example.test"
	cfg.Challenge.Enabled = false
	cfg.Admin.Enabled = true
	cfg.Admin.Token = testAdminToken
	if customize != nil {
		customize(&cfg)
	}
	store := memory.New(100)
	t.Cleanup(store.Close)
	rules, err := access.NewRuleSet(cfg.Whitelist, cfg.Blacklist, cfg.WhitelistUserAgents)
	if err != nil {
		t.Fatalf("access.NewRuleSet() error = %v", err)
	}
	scores, err := trust.NewScoreManager(store, cfg)
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	server, err := NewServer(cfg, store, scores, rules, time.Now())
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	return server
}

func requestWithAuth(method string, path string, body string) *http.Request {
	var reader *bytes.Reader
	if body == "" {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader([]byte(body))
	}
	request := httptest.NewRequest(method, "http://admin.test"+path, reader)
	request.Header.Set("Authorization", "Bearer "+testAdminToken)
	request.Header.Set("Content-Type", "application/json")
	return request
}

// FR-20 : une entrée de blacklist ajoutée via l'API est remise au cluster.
func TestAdminBlacklistAddNotifiesObserver(t *testing.T) {
	server := newTestServer(t)
	var published []string
	server.WithBlacklistObserver(func(value string) { published = append(published, value) })

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, requestWithAuth(http.MethodPost, "/waf/admin/blacklist", `{"ip":"5.5.5.5"}`))

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", response.Code)
	}
	if len(published) != 1 || published[0] != "5.5.5.5" {
		t.Fatalf("published = %v, want [5.5.5.5]", published)
	}
}

// FR-20 : une entrée reçue du cluster ne doit pas être effacée par la
// modification admin locale suivante, qui réécrit le RuleSet entier.
func TestClusterBlacklistEntrySurvivesLocalAdminChanges(t *testing.T) {
	server := newTestServer(t)
	handler := server.Handler()
	if err := server.ApplyClusterBlacklist("9.9.9.9"); err != nil {
		t.Fatalf("ApplyClusterBlacklist() error = %v", err)
	}

	for _, request := range []*http.Request{
		requestWithAuth(http.MethodPost, "/waf/admin/blacklist", `{"ip":"1.2.3.4"}`),
		requestWithAuth(http.MethodDelete, "/waf/admin/blacklist/1.2.3.4", ""),
	} {
		handler.ServeHTTP(httptest.NewRecorder(), request)
		if ok, _ := server.accessRules.IsBlacklisted("9.9.9.9"); !ok {
			t.Fatalf("cluster entry purged by %s %s", request.Method, request.URL.Path)
		}
	}

	var published []string
	server.WithBlacklistObserver(func(value string) { published = append(published, value) })
	if err := server.ApplyClusterBlacklist("8.8.8.8"); err != nil {
		t.Fatalf("ApplyClusterBlacklist() error = %v", err)
	}
	if len(published) != 0 {
		t.Fatalf("published = %v, want a propagated entry never re-published", published)
	}
	entries := server.state.ListBlacklist()
	if len(entries) != 2 || entries[0].Reason != clusterBlacklistReason {
		t.Fatalf("blacklist = %+v, want both cluster entries listed with reason %q", entries, clusterBlacklistReason)
	}
}
