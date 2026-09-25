package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

// Invariant #3 : toute forme de données est fermée. Dans chaque schéma de
// specs/schemas, un objet qui déclare ses properties — imbriqué compris —
// porte additionalProperties: false. alert.schema.json laissait `data` ouvert.
func TestEverySchemaObjectIsClosed(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "specs", "schemas", "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("list schemas: %v (found %d)", err, len(paths))
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var schema any
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
		walkOpenSchemaObjects(schema, "#", func(pointer string) {
			t.Errorf("%s%s declares properties without additionalProperties: false", filepath.Base(path), pointer)
		})
	}
}

func walkOpenSchemaObjects(node any, pointer string, report func(string)) {
	switch value := node.(type) {
	case map[string]any:
		_, hasProperties := value["properties"]
		if hasProperties && isObjectType(value["type"]) && value["additionalProperties"] != false {
			report(pointer)
		}
		for key, child := range value {
			walkOpenSchemaObjects(child, pointer+"/"+key, report)
		}
	case []any:
		for i, child := range value {
			walkOpenSchemaObjects(child, pointer+"/"+strconv.Itoa(i), report)
		}
	}
}

// isObjectType reconnaît "object" comme ["object", "null"].
func isObjectType(declared any) bool {
	switch value := declared.(type) {
	case string:
		return value == "object"
	case []any:
		return slices.Contains(value, any("object"))
	}
	return false
}
