// Package rules implémente un moteur de règles personnalisées (FR-17) basé sur
// un DSL YAML (cf. specs/schemas/rule.schema.json) compilé en structures Go au
// chargement. Les règles sont évaluées par priorité croissante ; la première
// qui matche exécute ses actions (short-circuit, sauf `continue: true`).
// Le jeu de règles est rechargeable à chaud via un atomic.Value.
package rules

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/gaetandev/waf/internal/middleware/cloudflare"

	"gopkg.in/yaml.v3"
)

// Rule est la forme YAML d'une règle (DSL).
type Rule struct {
	Name       string      `yaml:"name"`
	Priority   int         `yaml:"priority"`
	Enabled    bool        `yaml:"enabled"`
	Continue   bool        `yaml:"continue"`
	Conditions []Condition `yaml:"conditions"`
	Actions    []Action    `yaml:"actions"`
}

type Condition struct {
	Field    string   `yaml:"field"`
	Operator string   `yaml:"operator"`
	Value    string   `yaml:"value"`
	Values   []string `yaml:"values"`
	Name     string   `yaml:"name"` // pour header/query_param
}

type Action struct {
	Type   string `yaml:"type"`
	Value  string `yaml:"value"`
	Delta  int    `yaml:"delta"`
	Header string `yaml:"header"`
}

// compiledRule précompile les regex/CIDR pour une évaluation O(1) par requête.
type compiledRule struct {
	rule     Rule
	matchers []matcher
}

type matcher func(*http.Request) bool

// RuleSet contient les règles compilées, triées par priorité. Rechargeable à
// chaud (atomic swap).
type RuleSet struct {
	compiled atomic.Value // []compiledRule
}

func NewRuleSet() *RuleSet {
	rs := &RuleSet{}
	rs.compiled.Store([]compiledRule{})
	return rs
}

// Load compile et installe un nouveau jeu de règles (hot-reload).
func (rs *RuleSet) Load(rules []Rule) error {
	compiled := make([]compiledRule, 0, len(rules))
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		matchers, err := compileConditions(rule.Conditions)
		if err != nil {
			return fmt.Errorf("rule %q: %w", rule.Name, err)
		}
		compiled = append(compiled, compiledRule{rule: rule, matchers: matchers})
	}
	sort.SliceStable(compiled, func(i, j int) bool {
		return compiled[i].rule.Priority < compiled[j].rule.Priority
	})
	rs.compiled.Store(compiled)
	return nil
}

// LoadFile lit un fichier YAML de règles et l'installe.
func (rs *RuleSet) LoadFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read rules file: %w", err)
	}
	var doc struct {
		Rules []Rule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse rules yaml: %w", err)
	}
	return rs.Load(doc.Rules)
}

// Match retourne les actions à appliquer pour la requête (première règle qui
// matche, plus celles à `continue`). nil si aucune règle ne matche.
func (rs *RuleSet) Match(r *http.Request) []Action {
	compiled, _ := rs.compiled.Load().([]compiledRule)
	var actions []Action
	for _, cr := range compiled {
		if !ruleMatches(cr, r) {
			continue
		}
		actions = append(actions, cr.rule.Actions...)
		if !cr.rule.Continue {
			break
		}
	}
	return actions
}

func ruleMatches(cr compiledRule, r *http.Request) bool {
	if len(cr.matchers) == 0 {
		return false
	}
	for _, m := range cr.matchers {
		if !m(r) {
			return false
		}
	}
	return true
}

func compileConditions(conditions []Condition) ([]matcher, error) {
	matchers := make([]matcher, 0, len(conditions))
	for _, c := range conditions {
		m, err := compileCondition(c)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, m)
	}
	return matchers, nil
}

func compileCondition(c Condition) (matcher, error) {
	switch c.Field {
	case "ip":
		return compileIP(c)
	case "user_agent":
		return compileString(c, func(r *http.Request) string { return r.UserAgent() })
	case "path":
		return compileString(c, func(r *http.Request) string { return r.URL.Path })
	case "method":
		return compileString(c, func(r *http.Request) string { return r.Method })
	case "country":
		return compileString(c, func(r *http.Request) string { return r.Header.Get("CF-IPCountry") })
	case "header":
		name := c.Name
		return compileString(c, func(r *http.Request) string { return r.Header.Get(name) })
	case "query_param":
		name := c.Name
		return compileString(c, func(r *http.Request) string { return r.URL.Query().Get(name) })
	case "trust_score":
		return compileTrustScore(c)
	default:
		return nil, fmt.Errorf("unsupported condition field %q", c.Field)
	}
}

// compileTrustScore évalue le trust score (header X-WAF-Score). Si le score
// n'est pas encore disponible (-1), la condition ne matche pas (gracieux).
func compileTrustScore(c Condition) (matcher, error) {
	threshold, err := strconv.Atoi(c.Value)
	if err != nil {
		return nil, fmt.Errorf("trust_score value must be an integer: %w", err)
	}
	switch c.Operator {
	case "lt":
		return func(r *http.Request) bool { s := trustScore(r); return s >= 0 && s < threshold }, nil
	case "lte":
		return func(r *http.Request) bool { s := trustScore(r); return s >= 0 && s <= threshold }, nil
	case "gt":
		return func(r *http.Request) bool { s := trustScore(r); return s >= 0 && s > threshold }, nil
	case "gte":
		return func(r *http.Request) bool { s := trustScore(r); return s >= 0 && s >= threshold }, nil
	default:
		return nil, fmt.Errorf("unsupported trust_score operator %q", c.Operator)
	}
}

func compileIP(c Condition) (matcher, error) {
	switch c.Operator {
	case "equals":
		return func(r *http.Request) bool { return clientIP(r) == c.Value }, nil
	case "in_list":
		set := toSet(c.Values)
		return func(r *http.Request) bool { _, ok := set[clientIP(r)]; return ok }, nil
	case "in_cidr":
		networks := make([]*net.IPNet, 0, len(c.Values)+1)
		for _, raw := range append(c.Values, c.Value) {
			if raw == "" {
				continue
			}
			_, n, err := net.ParseCIDR(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid cidr %q: %w", raw, err)
			}
			networks = append(networks, n)
		}
		return func(r *http.Request) bool {
			ip := net.ParseIP(clientIP(r))
			for _, n := range networks {
				if n.Contains(ip) {
					return true
				}
			}
			return false
		}, nil
	default:
		return nil, fmt.Errorf("unsupported ip operator %q", c.Operator)
	}
}

func compileString(c Condition, extract func(*http.Request) string) (matcher, error) {
	switch c.Operator {
	case "equals":
		return func(r *http.Request) bool { return extract(r) == c.Value }, nil
	case "contains":
		return func(r *http.Request) bool { return strings.Contains(extract(r), c.Value) }, nil
	case "starts_with":
		return func(r *http.Request) bool { return strings.HasPrefix(extract(r), c.Value) }, nil
	case "ends_with":
		return func(r *http.Request) bool { return strings.HasSuffix(extract(r), c.Value) }, nil
	case "exists":
		return func(r *http.Request) bool { return extract(r) != "" }, nil
	case "in_list":
		set := toSet(c.Values)
		return func(r *http.Request) bool { _, ok := set[extract(r)]; return ok }, nil
	case "matches_regex":
		re, err := regexp.Compile(c.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", c.Value, err)
		}
		return func(r *http.Request) bool { return re.MatchString(extract(r)) }, nil
	default:
		return nil, fmt.Errorf("unsupported operator %q for field %q", c.Operator, c.Field)
	}
}

// clientIP retourne l'IP réelle établie par le WAF : CF-Connecting-IP validée
// contre les plages Cloudflare quand cloudflare.trusted, sinon l'adresse de la
// connexion. C'est le même chemin que la whitelist, la blacklist, le rate limit
// et le trust score — une seule résolution d'IP pour toutes les décisions.
//
// Cette fonction lisait auparavant X-Real-IP en priorité (FR-17 v2.3.0). C'est un
// en-tête *sortant*, posé par internal/proxy vers l'upstream ; en entrée il vient
// du client et Cloudflare ne le réécrit pas. Une règle `ip in_cidr` de blocage
// était donc contournable par un simple X-Real-IP, et une règle d'attribution de
// score usurpable.
func clientIP(r *http.Request) string {
	return cloudflare.RealIP(r)
}

func toSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	return set
}

// trustScore lit le header X-WAF-Score s'il est présent (sinon -1).
func trustScore(r *http.Request) int {
	if v := r.Header.Get("X-WAF-Score"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return -1
}
