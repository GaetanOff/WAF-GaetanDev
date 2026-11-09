package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// FR-41 (non-browser-paths.feature, « Motif invalide refusé au démarrage ») :
// un motif mal formé échoue au démarrage avec un message qui cite l'entrée.
func TestValidateNonBrowserPaths(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		wantErr  string // vide : configuration valide
	}{
		{name: "absent key", patterns: nil},
		{name: "empty list", patterns: []string{}},
		{name: "prefix and exact", patterns: []string{"/v1/", "/webhook"}},
		{name: "nested prefix", patterns: []string{"/api/v2/hooks/"}},
		{name: "dots inside a segment", patterns: []string{"/v1.2/x", "/.well-known/", "/..."}},
		{name: "non ascii segment", patterns: []string{"/café/"}},
		{name: "32 entries", patterns: numberedPaths(32)},
		{name: "relative", patterns: []string{"v1/"}, wantErr: `domains[0].non_browser_paths[0] must start with "/"`},
		{name: "root alone", patterns: []string{"/"}, wantErr: `domains[0].non_browser_paths[0] must not be "/" (would exempt the whole domain)`},
		{name: "empty", patterns: []string{""}, wantErr: "domains[0].non_browser_paths[0] must not be empty"},
		{name: "glob", patterns: []string{"/v1/*"}, wantErr: "domains[0].non_browser_paths[0] must not contain wildcard or query characters"},
		{name: "parent segment", patterns: []string{"/v1/../x/"}, wantErr: `domains[0].non_browser_paths[0] must not contain "..", "." segments or "//"`},
		{name: "current segment", patterns: []string{"/v1/./x"}, wantErr: `domains[0].non_browser_paths[0] must not contain "..", "." segments or "//"`},
		{name: "double slash", patterns: []string{"//v1/"}, wantErr: `domains[0].non_browser_paths[0] must not contain "..", "." segments or "//"`},
		{name: "trailing double slash", patterns: []string{"/v1//"}, wantErr: `domains[0].non_browser_paths[0] must not contain "..", "." segments or "//"`},
		{name: "query", patterns: []string{"/v1/?a=b"}, wantErr: "domains[0].non_browser_paths[0] must not contain wildcard or query characters"},
		{name: "fragment", patterns: []string{"/v1#x"}, wantErr: "domains[0].non_browser_paths[0] must not contain wildcard or query characters"},
		{name: "space", patterns: []string{"/v1 x"}, wantErr: "domains[0].non_browser_paths[0] must not contain spaces or control characters"},
		{name: "control", patterns: []string{"/v1\x00"}, wantErr: "domains[0].non_browser_paths[0] must not contain spaces or control characters"},
		{name: "too long", patterns: []string{"/" + strings.Repeat("a", 256)}, wantErr: "domains[0].non_browser_paths[0] must not exceed 256 characters"},
		{name: "second entry cited", patterns: []string{"/v1/", "/v1/../x"}, wantErr: "domains[0].non_browser_paths[1]"},
		{name: "duplicate", patterns: []string{"/v1/", "/v1/"}, wantErr: `domains[0].non_browser_paths has duplicate entry "/v1/"`},
		{name: "33 entries", patterns: numberedPaths(33), wantErr: "domains[0].non_browser_paths must not exceed 32 entries"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.Domains = []DomainConfig{{Host: "captcha.example.com", Upstream: "http://10.0.0.1", NonBrowserPaths: tt.patterns}}

			err := cfg.Validate()

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() unexpected error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() expected an error naming %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// L'index cité est celui de l'entrée domains[] fautive.
func TestValidateNonBrowserPathsCitesTheDomainIndex(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Domains = []DomainConfig{
		{Host: "www.example.com", Upstream: "http://10.0.0.1"},
		{Host: "captcha.example.com", Upstream: "http://10.0.0.2", NonBrowserPaths: []string{"v1/"}},
	}

	err := cfg.Validate()

	if err == nil || !strings.Contains(err.Error(), `domains[1].non_browser_paths[0] must start with "/"`) {
		t.Fatalf("Validate() error = %v, want domains[1].non_browser_paths[0]", err)
	}
}

func TestLoadDomainNonBrowserPaths(t *testing.T) {
	t.Setenv(envChallengeSecretKey, testSecret)
	t.Setenv(envAdminToken, testSecret)

	path := writeConfig(t, `
version: "1.0"
server:
  listen: ":8080"
upstream:
  address: "http://example.test"
domains:
  - host: "captcha.example.com"
    upstream: "http://10.0.0.1:8080"
    challenge_enabled: false
    non_browser_paths: ["/v1/", "/webhook"]
  - host: "www.example.com"
    upstream: "http://10.0.0.2:80"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := cfg.Domains[0].NonBrowserPaths; !slices.Equal(got, []string{"/v1/", "/webhook"}) {
		t.Fatalf("domains[0].non_browser_paths = %v, want [/v1/ /webhook]", got)
	}
	if got := cfg.Domains[1].NonBrowserPaths; len(got) != 0 {
		t.Fatalf("absent non_browser_paths = %v, want none", got)
	}
}

// FR-41 : le pattern de config.schema.json et config.Validate acceptent et
// refusent les mêmes motifs. Le pattern est compilé par regexp (RE2) : un
// pattern à assertion avant (lookahead), valide en ECMA-262 seulement,
// échouerait ici.
func TestNonBrowserPathsSchemaMatchesValidate(t *testing.T) {
	property := nonBrowserPathsSchema(t)
	items, _ := property["items"].(map[string]any)
	pattern, err := regexp.Compile(items["pattern"].(string))
	if err != nil {
		t.Fatalf("schema pattern is not RE2-compatible: %v", err)
	}
	minLength := int(items["minLength"].(float64))
	maxLength := int(items["maxLength"].(float64))
	if maxLength != maxNonBrowserPathLength {
		t.Fatalf("schema maxLength = %d, Go limit = %d", maxLength, maxNonBrowserPathLength)
	}
	if maxItems := int(property["maxItems"].(float64)); maxItems != maxNonBrowserPaths {
		t.Fatalf("schema maxItems = %d, Go limit = %d", maxItems, maxNonBrowserPaths)
	}
	if property["uniqueItems"] != true {
		t.Fatal("schema must declare uniqueItems: true (duplicates are refused)")
	}

	for _, candidate := range nonBrowserPathCandidates() {
		length := utf8.RuneCountInString(candidate)
		schemaValid := pattern.MatchString(candidate) && length >= minLength && length <= maxLength
		goValid := nonBrowserPathProblem(candidate) == ""
		if schemaValid != goValid {
			t.Errorf("motif %q: schema valid = %v, config.Validate valid = %v", candidate, schemaValid, goValid)
		}
	}
}

func nonBrowserPathsSchema(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "specs", "schemas", "config.schema.json"))
	if err != nil {
		t.Fatalf("read config.schema.json: %v", err)
	}
	var schema struct {
		Definitions struct {
			DomainConfig struct {
				Properties map[string]map[string]any `json:"properties"`
			} `json:"DomainConfig"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse config.schema.json: %v", err)
	}
	property, ok := schema.Definitions.DomainConfig.Properties["non_browser_paths"]
	if !ok {
		t.Fatal("config.schema.json: DomainConfig.non_browser_paths is missing")
	}
	return property
}

// nonBrowserPathCandidates couvre chaque règle des deux côtés de sa frontière.
func nonBrowserPathCandidates() []string {
	candidates := []string{
		"", "/", "//", "///", "v1", "v1/", "/v1", "/v1/", "/webhook", "/a/b/c/", "/V1/Site",
		"/.", "/..", "/./", "/../", "/...", "/.../", "/.a", "/..a", "/a.", "/a..", "/a.b/",
		"/.well-known/", "/v1/.", "/v1/..", "/v1/./x", "/v1/../x/", "/v1/.../x",
		"//v1/", "/v1//", "/v1//x", "/v1/x//",
		"/v1/*", "/v1?", "/v1/?a=b", "/v1#a", "/*", "/?", "/#",
		"/v1 x", "/v1\tx", "/v1\nx", "/v1\x00", "/v1\x1f", "/v1\x7f", "/v1\u0085", "/v1\u009f",
		"/café/", "/v1 x", "/日本/", "/a%2F..%2Fb", "/v1;x", "/~user/", "/a:b",
		"/" + strings.Repeat("a", 254), "/" + strings.Repeat("a", 255), "/" + strings.Repeat("a", 256),
		"/" + strings.Repeat("é", 255), "/" + strings.Repeat("é", 256),
	}
	return candidates
}

func numberedPaths(count int) []string {
	paths := make([]string, count)
	for i := range paths {
		paths[i] = fmt.Sprintf("/api-%d/", i)
	}
	return paths
}
