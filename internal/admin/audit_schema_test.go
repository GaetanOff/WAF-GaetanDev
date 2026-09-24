package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/gaetandev/waf/internal/config"
)

// Conformance : les entrées servies par GET /waf/admin/audit, pour chaque
// action d'administration, respectent specs/schemas/audit-entry.schema.json.
func TestAuditEntriesMatchAuditEntrySchema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "specs", "schemas", "audit-entry.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Required   []string `json:"required"`
		Properties map[string]struct {
			Enum []string `json:"enum"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	server := newTestServerWith(t, func(cfg *config.Config) { cfg.Audit.Enabled = true })
	server.WithConfigApplier(func(config.Config) {})
	visitor := server.scores.Set("1.2.3.4", "example.test", 60)
	for _, call := range []struct{ method, path, body string }{
		{http.MethodPost, "/waf/admin/whitelist", `{"ip":"10.0.0.1"}`},
		{http.MethodDelete, "/waf/admin/whitelist/10.0.0.1", ""},
		{http.MethodPost, "/waf/admin/blacklist", `{"ip":"10.0.0.2"}`},
		{http.MethodDelete, "/waf/admin/blacklist/10.0.0.2", ""},
		{http.MethodDelete, "/waf/admin/visitors/" + visitor.IPHash, ""},
		{http.MethodPatch, "/waf/admin/config", `{"rate_limit":{"burst":40}}`},
		{http.MethodPost, "/waf/admin/gdpr/erase", `{"ip":"1.2.3.4"}`},
	} {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, requestWithAuth(call.method, call.path, call.body))
		if response.Code >= 300 {
			t.Fatalf("%s %s: status = %d body = %s", call.method, call.path, response.Code, response.Body.String())
		}
	}

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, requestWithAuth(http.MethodGet, "/waf/admin/audit", ""))
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	if len(body.Items) != 7 {
		t.Fatalf("audit entries = %d, want 7", len(body.Items))
	}
	for _, entry := range body.Items {
		for _, name := range schema.Required {
			if _, ok := entry[name]; !ok {
				t.Fatalf("entry %v missing required %q", entry, name)
			}
		}
		for name, value := range entry {
			property, ok := schema.Properties[name]
			if !ok {
				t.Fatalf("entry %v has property %q absent from the schema", entry, name)
			}
			if len(property.Enum) > 0 && !slices.Contains(property.Enum, value.(string)) {
				t.Fatalf("entry %v: %q = %v not in %v", entry, name, value, property.Enum)
			}
		}
	}
}
