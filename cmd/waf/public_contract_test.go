package main

import (
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gaetandev/waf/internal/acme"
	"github.com/gaetandev/waf/internal/config"
	"gopkg.in/yaml.v3"
)

type publicResponse struct {
	Ref     string         `yaml:"$ref"`
	Headers map[string]any `yaml:"headers"`
	Content map[string]any `yaml:"content"`
}

type publicOperation struct {
	OperationID string                    `yaml:"operationId"`
	Responses   map[string]publicResponse `yaml:"responses"`
}

// publicPathItem retient les opérations d'un chemin, par méthode ; les autres
// champs du Path Item (servers, parameters…) sont ignorés.
type publicPathItem map[string]publicOperation

func (p *publicPathItem) UnmarshalYAML(node *yaml.Node) error {
	var fields map[string]yaml.Node
	if err := node.Decode(&fields); err != nil {
		return err
	}
	*p = publicPathItem{}
	for name, field := range fields {
		if !slices.Contains(httpMethods, name) {
			continue
		}
		var operation publicOperation
		if err := field.Decode(&operation); err != nil {
			return err
		}
		(*p)[name] = operation
	}
	return nil
}

var httpMethods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

type publicContract struct {
	Paths      map[string]publicPathItem `yaml:"paths"`
	Components struct {
		Responses map[string]publicResponse `yaml:"responses"`
	} `yaml:"components"`
}

type contractProbe struct {
	method, path, body string
}

func loadPublicContract(t *testing.T) publicContract {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "specs", "api", "public.openapi.yaml"))
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	var contract publicContract
	if err := yaml.Unmarshal(raw, &contract); err != nil {
		t.Fatalf("decode contract: %v", err)
	}
	return contract
}

// resolve suit une référence #/components/responses/<nom>.
func (c publicContract) resolve(response publicResponse) publicResponse {
	const prefix = "#/components/responses/"
	if strings.HasPrefix(response.Ref, prefix) {
		return c.Components.Responses[strings.TrimPrefix(response.Ref, prefix)]
	}
	return response
}

// assertConforms vérifie que la réponse (statut, type de contenu) est l'une de
// celles que le contrat décrit pour la sonde.
func (c publicContract) assertConforms(t *testing.T, probe contractProbe, response *httptest.ResponseRecorder) {
	t.Helper()
	operations, ok := c.Paths[probe.path]
	if !ok {
		t.Fatalf("%s is served but absent from public.openapi.yaml", probe.path)
	}
	operation, described := operations[strings.ToLower(probe.method)]
	if !described {
		// Méthode non décrite : la seule opération du chemin doit alors
		// documenter le 405, et c'est ce que le WAF doit répondre.
		for _, only := range operations {
			operation = only
		}
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s answered %d, want 405 for an undescribed method", probe.method, probe.path, response.Code)
		}
	}
	if operation.OperationID == "" {
		t.Fatalf("%s %s: operation without operationId", probe.method, probe.path)
	}
	documented, ok := operation.Responses[strconv.Itoa(response.Code)]
	if !ok {
		t.Fatalf("%s %s answered %d, not a documented response", probe.method, probe.path, response.Code)
	}
	documented = c.resolve(documented)
	if len(documented.Content) == 0 {
		return
	}
	got, _, _ := mime.ParseMediaType(response.Header().Get("Content-Type"))
	if _, ok := documented.Content[got]; !ok {
		t.Fatalf("%s %s %d: Content-Type = %q, not among the documented %v", probe.method, probe.path, response.Code, got, documented.Content)
	}
}

func publicTestHandler(t *testing.T, cfg config.Config) http.Handler {
	t.Helper()
	cfg.Cloudflare.Trusted = false
	cfg.OriginProtection.Enabled = true
	cfg.OriginProtection.Secret = strings.Repeat("s", 32)
	return routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("%s %s reached the upstream: /waf/ endpoints are served by the WAF", r.Method, r.URL.Path)
	}))
}

func serveProbe(handler http.Handler, probe contractProbe, host string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(probe.method, "http://"+host+probe.path, strings.NewReader(probe.body))
	request.RemoteAddr = "198.51.100.10:443"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

// Invariant #2 : chaque endpoint public du WAF a son contrat, et ses réponses
// (statut, type de contenu) sont celles que public.openapi.yaml décrit. Aucun
// de ces chemins n'atteint l'upstream.
func TestPublicEndpointsConformToTheirContract(t *testing.T) {
	contract := loadPublicContract(t)
	handler := publicTestHandler(t, config.Default())

	probes := []contractProbe{
		{http.MethodPost, "/waf/verify", `{}`},
		{http.MethodGet, "/waf/verify", ""},
		{http.MethodGet, "/waf/origin/verify", ""},
		{http.MethodGet, "/waf/metrics", ""},
		{http.MethodGet, "/waf/health", ""},
		{http.MethodPost, "/waf/health", ""},
		{http.MethodDelete, "/waf/metrics", ""},
		{http.MethodPost, "/waf/origin/verify", ""},
	}
	probed := map[string]bool{}
	for _, probe := range probes {
		contract.assertConforms(t, probe, serveProbe(handler, probe, "example.test"))
		probed[probe.path] = true
	}
	// Serveur annexe HTTP-01 (acme.http_challenge_listen), hors de routes().
	acmeHandler := acme.NewManager(config.ACME{Domains: []string{"example.test"}, CacheDir: t.TempDir()}).HTTPHandler(nil)
	acmeProbe := contractProbe{http.MethodGet, "/.well-known/acme-challenge/unknown-token", ""}
	for host, want := range map[string]int{"example.test": http.StatusNotFound, "other.test": http.StatusForbidden} {
		response := serveProbe(acmeHandler, acmeProbe, host)
		if response.Code != want {
			t.Fatalf("ACME challenge on %s: status = %d, want %d", host, response.Code, want)
		}
		acmeProbe.path = "/.well-known/acme-challenge/{token}"
		contract.assertConforms(t, acmeProbe, response)
		acmeProbe.path = "/.well-known/acme-challenge/unknown-token"
	}
	probed["/.well-known/acme-challenge/{token}"] = true
	for path := range contract.Paths {
		if !probed[path] {
			t.Errorf("public.openapi.yaml describes %s, which this test does not probe", path)
		}
	}
}

// Les refus d'enveloppe (envelopeGuard) s'appliquent à tout chemin servi,
// /waf/health excepté : le 400 strict_host est au contrat de chaque endpoint
// gardé, comme le 429 slowloris.
func TestEnvelopeRefusalsAreDocumented(t *testing.T) {
	contract := loadPublicContract(t)
	cfg := config.Default()
	cfg.Server.StrictHost = true
	cfg.Domains = []config.DomainConfig{{Host: "example.test", Upstream: "http://127.0.0.1:1"}}
	handler := publicTestHandler(t, cfg)

	for _, probe := range []contractProbe{
		{http.MethodPost, "/waf/verify", `{}`},
		{http.MethodGet, "/waf/origin/verify", ""},
		{http.MethodGet, "/waf/metrics", ""},
	} {
		response := serveProbe(handler, probe, "undeclared.test")
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s %s on an undeclared Host: status = %d, want 400", probe.method, probe.path, response.Code)
		}
		contract.assertConforms(t, probe, response)
		if _, ok := contract.Paths[probe.path][strings.ToLower(probe.method)].Responses["429"]; !ok {
			t.Errorf("%s %s: slowloris 429 undocumented", probe.method, probe.path)
		}
	}
}

// Les en-têtes que POST /waf/verify renvoie sont au contrat : no-store et la
// décision journalisée (X-WAF-Action, X-WAF-Reason) sur un refus JSON, la
// décision seule sur un 405.
func TestVerifyResponseHeadersAreDocumented(t *testing.T) {
	contract := loadPublicContract(t)
	handler := publicTestHandler(t, config.Default())
	responses := contract.Paths["/waf/verify"]["post"].Responses

	for _, tc := range []struct {
		probe   contractProbe
		headers []string
	}{
		{contractProbe{http.MethodPost, "/waf/verify", `{}`}, []string{"Cache-Control", "Pragma", "Expires", "X-WAF-Action", "X-WAF-Reason"}},
		{contractProbe{http.MethodGet, "/waf/verify", ""}, []string{"X-WAF-Action", "X-WAF-Reason"}},
	} {
		response := serveProbe(handler, tc.probe, "example.test")
		documented := contract.resolve(responses[strconv.Itoa(response.Code)])
		for _, name := range tc.headers {
			if response.Header().Get(name) == "" {
				t.Fatalf("%s %s %d: %s not sent", tc.probe.method, tc.probe.path, response.Code, name)
			}
			if _, ok := documented.Headers[name]; !ok {
				t.Errorf("%s %s %d sends %s, absent from the contract", tc.probe.method, tc.probe.path, response.Code, name)
			}
		}
	}
}
