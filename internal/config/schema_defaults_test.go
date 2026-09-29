package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

// runtimeDefaults sont les clés dont le défaut du schéma est appliqué au
// démarrage et non par Default() (la valeur vide y vaut « défaut »).
var runtimeDefaults = map[string]bool{
	"cluster.channel": true, // "waf:events", appliqué par buildCluster
}

// Chaque "default" de config.schema.json est celui de Default() : le schéma
// annonçait min_elapsed_ms 500, max_elapsed_ms 10000 et shadow_mode false,
// alors que le code démarre avec 0, 60000 et true.
func TestSchemaDefaultsMatchDefaultConfig(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "specs", "schemas", "config.schema.json"))
	if err != nil {
		t.Fatalf("read config.schema.json: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse config.schema.json: %v", err)
	}
	encoded, err := yaml.Marshal(Default())
	if err != nil {
		t.Fatalf("marshal Default(): %v", err)
	}
	var defaults map[string]any
	if err := yaml.Unmarshal(encoded, &defaults); err != nil {
		t.Fatalf("decode Default(): %v", err)
	}
	checked := compareSchemaDefaults(t, "", schema, defaults)
	if checked == 0 {
		t.Fatal("no schema default compared: the walk is broken")
	}
}

// compareSchemaDefaults parcourt les "properties" du schéma en parallèle de la
// configuration par défaut et retourne le nombre de défauts comparés. Une clé
// absente de Default() (bloc optionnel nil) n'est pas comparée.
func compareSchemaDefaults(t *testing.T, path string, node map[string]any, value any) int {
	t.Helper()
	checked := 0
	if want, ok := node["default"]; ok && value != nil && !runtimeDefaults[path] {
		checked++
		if !reflect.DeepEqual(jsonValue(t, want), jsonValue(t, value)) {
			t.Errorf("%s: schema default %v, Default() %v", path, want, value)
		}
	}
	properties, _ := node["properties"].(map[string]any)
	values, _ := value.(map[string]any)
	for key, property := range properties {
		child, _ := property.(map[string]any)
		childPath := key
		if path != "" {
			childPath = path + "." + key
		}
		checked += compareSchemaDefaults(t, childPath, child, values[key])
	}
	return checked
}

// jsonValue ramène une valeur YAML ou JSON à sa forme JSON décodée (nombres en
// float64) pour comparer des types homogènes.
func jsonValue(t *testing.T, value any) any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %v: %v", value, err)
	}
	var decoded any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal %s: %v", encoded, err)
	}
	return decoded
}
