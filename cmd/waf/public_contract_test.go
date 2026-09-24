package main

import (
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gaetandev/waf/internal/config"
	"gopkg.in/yaml.v3"
)

type publicContract struct {
	Paths map[string]map[string]struct {
		OperationID string `yaml:"operationId"`
		Responses   map[string]struct {
			Content map[string]any `yaml:"content"`
		} `yaml:"responses"`
	} `yaml:"paths"`
}

// Invariant #2 : chaque endpoint public du WAF a son contrat, et ses réponses
// (statut, type de contenu) sont celles que public.openapi.yaml décrit. Aucun
// de ces chemins n'atteint l'upstream.
func TestPublicEndpointsConformToTheirContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "specs", "api", "public.openapi.yaml"))
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	var contract publicContract
	if err := yaml.Unmarshal(raw, &contract); err != nil {
		t.Fatalf("decode contract: %v", err)
	}

	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.OriginProtection.Enabled = true
	cfg.OriginProtection.Secret = strings.Repeat("s", 32)
	handler := routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Fatalf("%s %s reached the upstream: /waf/ endpoints are served by the WAF", r.Method, r.URL.Path)
	}))

	probes := []struct {
		method, path, body string
	}{
		{http.MethodPost, "/waf/verify", `{}`},
		{http.MethodGet, "/waf/verify", ""},
		{http.MethodGet, "/waf/origin/verify", ""},
		{http.MethodGet, "/waf/metrics", ""},
		{http.MethodGet, "/waf/health", ""},
	}
	probed := map[string]bool{}
	for _, probe := range probes {
		request := httptest.NewRequest(probe.method, "http://example.test"+probe.path, strings.NewReader(probe.body))
		request.RemoteAddr = "198.51.100.10:443"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)

		operations, ok := contract.Paths[probe.path]
		if !ok {
			t.Fatalf("%s is served but absent from public.openapi.yaml", probe.path)
		}
		operation, ok := operations[strings.ToLower(probe.method)]
		if !ok {
			// Méthode non décrite : le contrat doit alors documenter le 405.
			operation = operations["post"]
		}
		probed[probe.path] = true
		if operation.OperationID == "" {
			t.Fatalf("%s %s: operation without operationId", probe.method, probe.path)
		}
		documented, ok := operation.Responses[strconv.Itoa(response.Code)]
		if !ok {
			t.Fatalf("%s %s answered %d, not a documented response", probe.method, probe.path, response.Code)
		}
		for contentType := range documented.Content {
			got, _, _ := mime.ParseMediaType(response.Header().Get("Content-Type"))
			if got != contentType {
				t.Fatalf("%s %s: Content-Type = %q, want %q", probe.method, probe.path, got, contentType)
			}
		}
	}
	for path := range contract.Paths {
		if !probed[path] {
			t.Errorf("public.openapi.yaml describes %s, which this test does not probe", path)
		}
	}
}
