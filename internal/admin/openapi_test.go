package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Invariant #2 : aucune route sans contrat. Chaque route servie par l'API
// admin a son opération (avec operationId) dans specs/api/admin.openapi.yaml,
// et le contrat ne décrit aucune opération absente du code.
func TestEveryAdminRouteHasAnOpenAPIOperation(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "specs", "api", "admin.openapi.yaml"))
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	var contract struct {
		Paths map[string]map[string]struct {
			OperationID string `yaml:"operationId"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &contract); err != nil {
		t.Fatalf("decode contract: %v", err)
	}

	served := map[string]bool{}
	for _, r := range newTestServer(t).routeTable() {
		key := strings.ToLower(r.method) + " " + r.specPath
		served[key] = true
		operation, ok := contract.Paths[r.specPath][strings.ToLower(r.method)]
		if !ok || operation.OperationID == "" {
			t.Errorf("%s %s is served but has no operation with an operationId in admin.openapi.yaml", r.method, r.specPath)
		}
	}
	for path, operations := range contract.Paths {
		for method := range operations {
			if !served[method+" "+path] {
				t.Errorf("admin.openapi.yaml describes %s %s, which the admin API does not serve", strings.ToUpper(method), path)
			}
		}
	}
}
