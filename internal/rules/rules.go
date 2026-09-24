// Package rules implémente un moteur de règles personnalisées (FR-17) basé sur
// un DSL YAML (cf. specs/schemas/rule.schema.json) compilé en structures Go au
// chargement. Les règles sont évaluées par priorité croissante ; la première
// qui matche exécute ses actions (short-circuit, sauf `continue: true`).
// Le jeu de règles est rechargeable à chaud via un atomic.Value.
package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
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

// supportedActions est l'ensemble des actions exécutées par Middleware.Handler.
// Une action hors de cet ensemble était chargée sans erreur puis ignorée : une
// règle `type: challenge` ou `type: rate_limit` ne protégeait rien, sans que
// l'opérateur le sache.
var supportedActions = map[string]struct{}{
	"block":       {},
	"tarpit":      {},
	"score_delta": {},
	"add_header":  {},
	"log":         {},
}

// compiledRule précompile les regex/CIDR pour une évaluation O(1) par requête.
type compiledRule struct {
	rule     Rule
	matchers []matcher
}

type matcher func(*requestView) bool

// requestView expose à l'évaluation les champs dérivés d'une requête, calculés
// au plus une fois par requête quel que soit le nombre de conditions qui les
// lisent. r.URL.Query() réanalysait la query string (et allouait une map) à
// chaque condition query_param de chaque règle.
type requestView struct {
	r        *http.Request
	query    url.Values
	parsed   bool
	clientIP string
	resolved bool
}

func (v *requestView) queryParam(name string) string {
	if !v.parsed {
		v.query, v.parsed = v.r.URL.Query(), true
	}
	return v.query.Get(name)
}

func (v *requestView) ip() string {
	if !v.resolved {
		v.clientIP, v.resolved = clientIP(v.r), true
	}
	return v.clientIP
}

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
		if err := validateActions(rule.Actions); err != nil {
			return fmt.Errorf("rule %q: %w", rule.Name, err)
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
//
// Le décodage est strict, comme celui de la configuration principale : une clé
// inconnue était ignorée, si bien qu'une règle écrite avec `op:` au lieu de
// `operator:`, ou avec un groupe `conditions: {operator: OR, items: …}`,
// perdait une partie de sa définition en silence.
func (rs *RuleSet) LoadFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read rules file: %w", err)
	}
	var doc struct {
		Rules []Rule `yaml:"rules"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("parse rules yaml: %w", err)
	}
	return rs.Load(doc.Rules)
}

func validateActions(actions []Action) error {
	if len(actions) == 0 {
		return errors.New("at least one action is required")
	}
	for _, action := range actions {
		if _, ok := supportedActions[action.Type]; !ok {
			return fmt.Errorf("unsupported action type %q (supported: block, tarpit, score_delta, add_header, log)", action.Type)
		}
	}
	return nil
}

// Match retourne les actions à appliquer pour la requête (première règle qui
// matche, plus celles à `continue`). nil si aucune règle ne matche.
func (rs *RuleSet) Match(r *http.Request) []Action {
	compiled, _ := rs.compiled.Load().([]compiledRule)
	view := &requestView{r: r}
	var actions []Action
	for _, cr := range compiled {
		if !ruleMatches(cr, view) {
			continue
		}
		actions = append(actions, cr.rule.Actions...)
		if !cr.rule.Continue {
			break
		}
	}
	return actions
}

func ruleMatches(cr compiledRule, view *requestView) bool {
	if len(cr.matchers) == 0 {
		return false
	}
	for _, m := range cr.matchers {
		if !m(view) {
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
		return compileString(c, func(v *requestView) string { return v.r.UserAgent() })
	case "path":
		return compileString(c, func(v *requestView) string { return v.r.URL.Path })
	case "method":
		return compileString(c, func(v *requestView) string { return v.r.Method })
	case "country":
		return compileString(c, func(v *requestView) string { return v.r.Header.Get("CF-IPCountry") })
	case "header":
		name := c.Name
		return compileString(c, func(v *requestView) string { return v.r.Header.Get(name) })
	case "query_param":
		name := c.Name
		return compileString(c, func(v *requestView) string { return v.queryParam(name) })
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
		return func(v *requestView) bool { s := trustScore(v.r); return s >= 0 && s < threshold }, nil
	case "lte":
		return func(v *requestView) bool { s := trustScore(v.r); return s >= 0 && s <= threshold }, nil
	case "gt":
		return func(v *requestView) bool { s := trustScore(v.r); return s >= 0 && s > threshold }, nil
	case "gte":
		return func(v *requestView) bool { s := trustScore(v.r); return s >= 0 && s >= threshold }, nil
	default:
		return nil, fmt.Errorf("unsupported trust_score operator %q", c.Operator)
	}
}

func compileIP(c Condition) (matcher, error) {
	switch c.Operator {
	case "equals":
		return func(v *requestView) bool { return v.ip() == c.Value }, nil
	case "in_list":
		set := toSet(c.Values)
		return func(v *requestView) bool { _, ok := set[v.ip()]; return ok }, nil
	case "in_cidr":
		// net/netip : adresses et préfixes par valeur, Contains sans allocation
		// (net.ParseIP allouait une slice par requête).
		prefixes := make([]netip.Prefix, 0, len(c.Values)+1)
		for _, raw := range append(c.Values, c.Value) {
			if raw == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid cidr %q: %w", raw, err)
			}
			prefixes = append(prefixes, prefix.Masked())
		}
		return func(v *requestView) bool {
			addr, err := netip.ParseAddr(v.ip())
			if err != nil {
				return false
			}
			addr = addr.Unmap() // ::ffff:a.b.c.d correspond aux préfixes IPv4
			for _, prefix := range prefixes {
				if prefix.Contains(addr) {
					return true
				}
			}
			return false
		}, nil
	default:
		return nil, fmt.Errorf("unsupported ip operator %q", c.Operator)
	}
}

func compileString(c Condition, extract func(*requestView) string) (matcher, error) {
	switch c.Operator {
	case "equals":
		return func(v *requestView) bool { return extract(v) == c.Value }, nil
	case "contains":
		return func(v *requestView) bool { return strings.Contains(extract(v), c.Value) }, nil
	case "starts_with":
		return func(v *requestView) bool { return strings.HasPrefix(extract(v), c.Value) }, nil
	case "ends_with":
		return func(v *requestView) bool { return strings.HasSuffix(extract(v), c.Value) }, nil
	case "exists":
		return func(v *requestView) bool { return extract(v) != "" }, nil
	case "in_list":
		set := toSet(c.Values)
		return func(v *requestView) bool { _, ok := set[extract(v)]; return ok }, nil
	case "matches_regex":
		re, err := regexp.Compile(c.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", c.Value, err)
		}
		return func(v *requestView) bool { return re.MatchString(extract(v)) }, nil
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
