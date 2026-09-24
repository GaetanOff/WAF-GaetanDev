package redis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/storage"
)

type visitorSchema struct {
	Required             []string `json:"required"`
	AdditionalProperties bool     `json:"additionalProperties"`
	Properties           map[string]struct {
		Type    any    `json:"type"`
		Pattern string `json:"pattern"`
	} `json:"properties"`
}

// Conformance : la valeur que le backend Redis écrit pour un visiteur respecte
// specs/schemas/visitor.schema.json (clés snake_case, champs requis, motifs,
// aucune propriété hors schéma). Avant les balises JSON, elle portait des clés
// PascalCase, toutes hors contrat.
func TestStoredVisitorMatchesVisitorSchema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "specs", "schemas", "visitor.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema visitorSchema
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	store, fake, _, clock := newTestStore(t, 100)
	expiresAt := clock.Now().Add(30 * time.Minute)
	fpHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	visitor := visitorFixture(expiresAt)
	visitor.IPHash = "0123456789abcdef"
	visitor.FPHash = &fpHash

	store.SetVisitor(visitor.IPHash, visitor)

	payload, _, ok := fake.rawValue(visitorKeyPrefix + visitor.IPHash)
	if !ok {
		t.Fatal("visitor not written to Redis")
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	for _, name := range schema.Required {
		if _, ok := document[name]; !ok {
			t.Fatalf("payload %s misses required %q", payload, name)
		}
	}
	for name, value := range document {
		property, ok := schema.Properties[name]
		if !ok {
			t.Fatalf("payload has property %q absent from the schema (additionalProperties: false)", name)
		}
		if !typeAllowed(property.Type, value) {
			t.Fatalf("payload %q = %v does not have schema type %v", name, value, property.Type)
		}
		if text, isText := value.(string); isText && property.Pattern != "" && !regexp.MustCompile(property.Pattern).MatchString(text) {
			t.Fatalf("payload %q = %q does not match %s", name, text, property.Pattern)
		}
	}
}

// typeAllowed vérifie le type JSON d'une valeur décodée contre le `type` d'une
// propriété (chaîne ou liste de chaînes).
func typeAllowed(schemaType any, value any) bool {
	var allowed []string
	switch typed := schemaType.(type) {
	case string:
		allowed = []string{typed}
	case []any:
		for _, item := range typed {
			if name, ok := item.(string); ok {
				allowed = append(allowed, name)
			}
		}
	}
	var actual string
	switch number := value.(type) {
	case nil:
		actual = "null"
	case string:
		actual = "string"
	case bool:
		actual = "boolean"
	case float64:
		if number == float64(int64(number)) && slices.Contains(allowed, "integer") {
			return true
		}
		actual = "number"
	default:
		actual = "object"
	}
	return slices.Contains(allowed, actual)
}

// Un visiteur écrit par une version antérieure (clés PascalCase) doit rester
// lisible : décodé en snake_case, il deviendrait un visiteur vide de score 0,
// donc bloqué, jusqu'à l'expiration de sa clé.
func TestLegacyPascalCaseVisitorStaysReadable(t *testing.T) {
	store, fake, _, clock := newTestStore(t, 100)
	legacy := legacyVisitorState(visitorFixture(clock.Now().Add(30 * time.Minute)))
	payload, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy visitor: %v", err)
	}
	fake.put(visitorKeyPrefix+legacy.IPHash, string(payload))

	got, found := store.GetVisitor(legacy.IPHash)

	if !found {
		t.Fatal("legacy visitor not found")
	}
	if got.Score != legacy.Score || got.IPHash != legacy.IPHash || !got.ChallengePassed {
		t.Fatalf("legacy visitor = %+v, want the PascalCase fields decoded", got)
	}
}

func TestDecodeVisitorRejectsAPayloadWithoutIdentity(t *testing.T) {
	if _, err := decodeVisitor([]byte(`{"score": 80}`)); err == nil {
		t.Fatal("decodeVisitor() error = nil, want a payload without ip_hash refused")
	}
	var zero storage.VisitorState
	if got, err := decodeVisitor([]byte(`{"ip_hash":"0123456789abcdef","score":80}`)); err != nil || got == zero {
		t.Fatalf("decodeVisitor() = %+v, %v, want the snake_case payload decoded", got, err)
	}
}
