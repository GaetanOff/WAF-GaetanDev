package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// upstream-pool.schema.json détaille le bloc upstream_pool de
// config.schema.json : mêmes contraintes, descriptions mises à part. La v2.0.0
// s'en disait identique sans l'être (minItems, définitions, défauts).
func TestUpstreamPoolSchemaMatchesTheConfigBlock(t *testing.T) {
	read := func(name string) map[string]any {
		raw, err := os.ReadFile(filepath.Join("..", "..", "specs", "schemas", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var schema map[string]any
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		return schema
	}
	pool := read("upstream-pool.schema.json")
	block := read("config.schema.json")["properties"].(map[string]any)["upstream_pool"].(map[string]any)
	for _, key := range []string{"$schema", "$id", "$comment", "title"} {
		delete(pool, key)
	}
	if got, want := withoutDescriptions(pool), withoutDescriptions(block); !reflect.DeepEqual(got, want) {
		t.Fatalf("upstream-pool.schema.json differs from config.schema.json#/properties/upstream_pool:\n%v\nwant\n%v", got, want)
	}
}

// withoutDescriptions copie un nœud de schéma sans ses descriptions.
func withoutDescriptions(node any) any {
	switch value := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for key, child := range value {
			if key != "description" {
				out[key] = withoutDescriptions(child)
			}
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, child := range value {
			out[i] = withoutDescriptions(child)
		}
		return out
	default:
		return value
	}
}
