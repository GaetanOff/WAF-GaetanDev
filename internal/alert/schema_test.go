package alert

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
)

type alertSchema struct {
	Required   []string `json:"required"`
	Properties map[string]struct {
		Enum      []string `json:"enum"`
		MaxLength int      `json:"maxLength"`
	} `json:"properties"`
}

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Conformance : le payload du sink générique respecte
// specs/schemas/alert.schema.json pour chaque trigger émis. Avant, `id` (requis)
// manquait et aucun trigger émis ne figurait dans l'enum du schéma.
func TestGenericPayloadMatchesAlertSchema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "specs", "schemas", "alert.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema alertSchema
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	notifier := NewNotifier(nil, 0, 0, nil)
	defer notifier.Close()

	seen := make(map[string]bool)
	for _, trigger := range []string{TriggerBlock, TriggerCircuitBreaker, TriggerHoneypot, TriggerUnderAttackStart, TriggerUnderAttackEnd} {
		alert := notifier.alertFor(Event{Trigger: trigger, Domain: "example.test", Reason: "r", IP: "1.2.3.4"})
		var document map[string]any
		if err := json.Unmarshal(encode(SinkGeneric, alert), &document); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		for _, name := range schema.Required {
			if _, ok := document[name]; !ok {
				t.Fatalf("%s payload misses required %q", trigger, name)
			}
		}
		for name, value := range document {
			property, ok := schema.Properties[name]
			if !ok {
				t.Fatalf("%s payload has property %q absent from the schema", trigger, name)
			}
			text, _ := value.(string)
			if len(property.Enum) > 0 && !slices.Contains(property.Enum, text) {
				t.Fatalf("%s payload: %q = %v not in %v", trigger, name, value, property.Enum)
			}
			if property.MaxLength > 0 && len([]rune(text)) > property.MaxLength {
				t.Fatalf("%s payload: %q longer than %d", trigger, name, property.MaxLength)
			}
		}
		id, _ := document["id"].(string)
		if !uuidV4.MatchString(id) || seen[id] {
			t.Fatalf("%s payload id = %q, want a fresh UUID v4", trigger, id)
		}
		seen[id] = true
	}
}
