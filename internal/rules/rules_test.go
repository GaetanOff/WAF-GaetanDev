package rules

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/trust"
)

func request(method string, target string, ip string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = ip + ":1234"
	return r
}

func TestRuleSetMatchesByPriorityAndShortCircuits(t *testing.T) {
	rs := NewRuleSet()
	err := rs.Load([]Rule{
		{
			Name: "low-prio-block", Priority: 100, Enabled: true,
			Conditions: []Condition{{Field: "path", Operator: "starts_with", Value: "/admin"}},
			Actions:    []Action{{Type: "block", Value: "rule_admin"}},
		},
		{
			Name: "high-prio-log", Priority: 1, Enabled: true, Continue: true,
			Conditions: []Condition{{Field: "path", Operator: "starts_with", Value: "/admin"}},
			Actions:    []Action{{Type: "log", Value: "admin_access"}},
		},
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	actions := rs.Match(request(http.MethodGet, "http://x/admin/users", "1.2.3.4"), nil)
	// La règle priorité 1 (continue) puis priorité 100 (block) → log puis block.
	if len(actions) != 2 || actions[0].Type != "log" || actions[1].Type != "block" {
		t.Fatalf("actions = %+v, want [log, block]", actions)
	}
}

func TestRuleConditionsIPCidrAndMethod(t *testing.T) {
	rs := NewRuleSet()
	if err := rs.Load([]Rule{{
		Name: "block-cidr-post", Priority: 10, Enabled: true,
		Conditions: []Condition{
			{Field: "ip", Operator: "in_cidr", Values: []string{"10.0.0.0/8"}},
			{Field: "method", Operator: "equals", Value: "POST"},
		},
		Actions: []Action{{Type: "block"}},
	}}); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if a := rs.Match(request(http.MethodPost, "http://x/", "10.1.2.3"), nil); len(a) != 1 {
		t.Fatalf("expected match for 10.1.2.3 POST, got %+v", a)
	}
	if a := rs.Match(request(http.MethodGet, "http://x/", "10.1.2.3"), nil); len(a) != 0 {
		t.Fatalf("GET must not match POST rule, got %+v", a)
	}
	if a := rs.Match(request(http.MethodPost, "http://x/", "8.8.8.8"), nil); len(a) != 0 {
		t.Fatalf("8.8.8.8 must not match CIDR rule, got %+v", a)
	}
}

func TestDisabledRuleIgnoredAndHotReload(t *testing.T) {
	rs := NewRuleSet()
	_ = rs.Load([]Rule{{
		Name: "disabled", Priority: 1, Enabled: false,
		Conditions: []Condition{{Field: "path", Operator: "equals", Value: "/x"}},
		Actions:    []Action{{Type: "block"}},
	}})
	if a := rs.Match(request(http.MethodGet, "http://x/x", "1.1.1.1"), nil); len(a) != 0 {
		t.Fatalf("disabled rule must not match, got %+v", a)
	}

	// Hot-reload : on installe une règle active.
	_ = rs.Load([]Rule{{
		Name: "active", Priority: 1, Enabled: true,
		Conditions: []Condition{{Field: "path", Operator: "equals", Value: "/x"}},
		Actions:    []Action{{Type: "block"}},
	}})
	if a := rs.Match(request(http.MethodGet, "http://x/x", "1.1.1.1"), nil); len(a) != 1 {
		t.Fatalf("reloaded rule must match, got %+v", a)
	}
}

func TestInvalidRegexConditionFailsToLoad(t *testing.T) {
	rs := NewRuleSet()
	err := rs.Load([]Rule{{
		Name: "bad", Priority: 1, Enabled: true,
		Conditions: []Condition{{Field: "user_agent", Operator: "matches_regex", Value: "([a-z"}},
		Actions:    []Action{{Type: "block"}},
	}})
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestMiddlewareBlocksOnRule(t *testing.T) {
	rs := NewRuleSet()
	_ = rs.Load([]Rule{{
		Name: "block-bad-ua", Priority: 1, Enabled: true,
		Conditions: []Condition{{Field: "user_agent", Operator: "contains", Value: "evilbot"}},
		Actions:    []Action{{Type: "block", Value: "rule_evilbot"}},
	}})
	req := request(http.MethodGet, "http://x/", "1.2.3.4")
	req.Header.Set("User-Agent", "evilbot/1.0")
	response := httptest.NewRecorder()

	NewMiddleware(rs, nil).Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("blocked request must not reach upstream")
	})).ServeHTTP(response, req)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if response.Header().Get("X-WAF-Reason") != "rule_evilbot" {
		t.Fatalf("reason = %q", response.Header().Get("X-WAF-Reason"))
	}
}

// FR-17 : la condition `ip` doit être résolue sur l'IP réelle établie par le WAF.
// clientIP lisait X-Real-IP en priorité — un en-tête *sortant* que Cloudflare ne
// réécrit pas en entrée, donc pilotable par le client.
func TestRuleIPConditionIgnoresClientSuppliedXRealIP(t *testing.T) {
	rs := NewRuleSet()
	if err := rs.Load([]Rule{{
		Name: "block-internal-range", Priority: 10, Enabled: true,
		Conditions: []Condition{{Field: "ip", Operator: "in_cidr", Values: []string{"10.0.0.0/8"}}},
		Actions:    []Action{{Type: "block"}},
	}}); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	tests := []struct {
		name      string
		remoteIP  string
		xRealIP   string
		wantMatch bool
	}{
		// Témoin : sans témoin, le test passerait même si la règle ne matchait jamais.
		{name: "temoin dans le cidr", remoteIP: "10.1.2.3", wantMatch: true},
		{name: "temoin hors cidr", remoteIP: "8.8.8.8", wantMatch: false},
		// Évasion : l'IP réelle est bloquée, le client prétend être ailleurs.
		{name: "evasion par x-real-ip", remoteIP: "10.1.2.3", xRealIP: "8.8.8.8", wantMatch: true},
		// Usurpation : l'IP réelle est hors périmètre, le client prétend être dedans.
		{name: "usurpation par x-real-ip", remoteIP: "8.8.8.8", xRealIP: "10.1.2.3", wantMatch: false},
		// X-Forwarded-For ne doit pas davantage peser sur la résolution.
		{name: "evasion par x-forwarded-for", remoteIP: "10.1.2.3", xRealIP: "", wantMatch: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := request(http.MethodGet, "http://x/", tt.remoteIP)
			if tt.xRealIP != "" {
				r.Header.Set("X-Real-IP", tt.xRealIP)
			}
			r.Header.Set("X-Forwarded-For", "203.0.113.9")

			matched := len(rs.Match(r, nil)) == 1
			if matched != tt.wantMatch {
				t.Fatalf("match = %v, want %v (remote %s, X-Real-IP %q)", matched, tt.wantMatch, tt.remoteIP, tt.xRealIP)
			}
		})
	}
}

// La résolution doit suivre le chemin Cloudflare quand il est établi : c'est
// l'IP posée dans le contexte par cloudflare.Middleware qui compte, pas RemoteAddr.
func TestRuleIPConditionUsesTheCloudflareEstablishedIP(t *testing.T) {
	rs := NewRuleSet()
	if err := rs.Load([]Rule{{
		Name: "block-internal-range", Priority: 10, Enabled: true,
		Conditions: []Condition{{Field: "ip", Operator: "in_cidr", Values: []string{"10.0.0.0/8"}}},
		Actions:    []Action{{Type: "block"}},
	}}); err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// 103.21.244.1 appartient aux plages Cloudflare : le middleware honore alors
	// CF-Connecting-IP et pose l'IP réelle dans le contexte.
	r := request(http.MethodGet, "http://x/", "103.21.244.1")
	r.Header.Set("CF-Connecting-IP", "10.1.2.3")

	var matched bool
	cloudflare.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, inner *http.Request) {
		matched = len(rs.Match(inner, nil)) == 1
	})).ServeHTTP(httptest.NewRecorder(), r)

	if !matched {
		t.Fatal("la règle doit matcher sur l'IP de CF-Connecting-IP validée, pas sur l'IP de l'edge Cloudflare")
	}
}

func BenchmarkMatchQueryParamRules(b *testing.B) {
	ruleSet := NewRuleSet()
	var rules []Rule
	for i := range 10 {
		rules = append(rules, Rule{
			Name: fmt.Sprintf("rule-%d", i), Priority: i, Enabled: true,
			Conditions: []Condition{
				{Field: "query_param", Name: fmt.Sprintf("p%d", i), Operator: "equals", Value: "block"},
				{Field: "ip", Operator: "in_cidr", Values: []string{"10.0.0.0/8", "192.168.0.0/16"}},
			},
			Actions: []Action{{Type: "block"}},
		})
	}
	if err := ruleSet.Load(rules); err != nil {
		b.Fatalf("Load() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.test/search?q=shoes&page=2&sort=asc", nil)
	request.RemoteAddr = "10.1.2.3:1234"
	b.ReportAllocs()
	for b.Loop() {
		ruleSet.Match(request, nil)
	}
}

// IPv4 mappé en IPv6 : netip distingue ::ffff:a.b.c.d de a.b.c.d, net.IPNet non.
func TestRuleIPCidrMatchesIPv4MappedAddress(t *testing.T) {
	ruleSet := NewRuleSet()
	if err := ruleSet.Load([]Rule{{Name: "cidr", Enabled: true, Conditions: []Condition{{Field: "ip", Operator: "in_cidr", Value: "10.0.0.0/8"}}, Actions: []Action{{Type: "block"}}}}); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "[::ffff:10.1.2.3]:1234"
	if len(ruleSet.Match(request, nil)) == 0 {
		t.Fatal("IPv4-mapped client address must match the IPv4 prefix")
	}
}

// Une action que le middleware n'exécute pas était chargée puis ignorée : la
// règle semblait active et ne protégeait rien.
func TestLoadRejectsUnsupportedActions(t *testing.T) {
	for _, actions := range [][]Action{
		{{Type: "challenge"}},
		{{Type: "rate_limit"}},
		{{Type: "allow"}},
		{{Type: "log"}, {Type: "redirect"}},
		{{Type: "add_header", Value: "1"}},
		{{Type: "add_header", Header: "X Bad", Value: "1"}},
		nil,
	} {
		rule := Rule{Name: "r", Enabled: true, Conditions: []Condition{{Field: "path", Operator: "equals", Value: "/x"}}, Actions: actions}
		if err := NewRuleSet().Load([]Rule{rule}); err == nil {
			t.Fatalf("Load(%v) error = nil, want the rule refused", actions)
		}
	}
}

func TestLoadAcceptsAddHeaderWithAHeaderName(t *testing.T) {
	rule := Rule{Name: "r", Enabled: true, Conditions: []Condition{{Field: "path", Operator: "equals", Value: "/x"}}, Actions: []Action{{Type: "add_header", Header: "X-API", Value: "1"}}}
	if err := NewRuleSet().Load([]Rule{rule}); err != nil {
		t.Fatalf("Load() error = %v, want the add_header rule loaded", err)
	}
}

// Une règle écrite selon une autre forme (`op:`, groupe OR) perdait en silence
// les clés inconnues : le fichier doit être refusé.
func TestLoadFileRejectsUnknownKeys(t *testing.T) {
	for name, content := range map[string]string{
		"op instead of operator": "rules:\n  - name: r\n    enabled: true\n    conditions:\n      - {field: path, op: equals, value: /x}\n    actions:\n      - {type: block}\n",
		"condition group":        "rules:\n  - name: r\n    enabled: true\n    conditions:\n      operator: OR\n      items: []\n    actions:\n      - {type: block}\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "rules.yaml")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatalf("write rules: %v", err)
			}
			if err := NewRuleSet().LoadFile(path); err == nil {
				t.Fatal("LoadFile() error = nil, want the file refused")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "rules.yaml")
	valid := "rules:\n  - name: r\n    enabled: true\n    conditions:\n      - {field: path, operator: equals, value: /x}\n    actions:\n      - {type: block}\n"
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := NewRuleSet().LoadFile(path); err != nil {
		t.Fatalf("LoadFile() valid file error = %v", err)
	}
}

func newScoreManager(t *testing.T) *trust.ScoreManager {
	t.Helper()
	scores, err := trust.NewScoreManager(memory.New(100), config.Default())
	if err != nil {
		t.Fatalf("trust.NewScoreManager() error = %v", err)
	}
	return scores
}

func lowTrustCheckoutRules(t *testing.T) *RuleSet {
	t.Helper()
	rs := NewRuleSet()
	if err := rs.Load([]Rule{{
		Name: "tarpit-low-trust-checkout", Priority: 1, Enabled: true,
		Conditions: []Condition{
			{Field: "trust_score", Operator: "lt", Value: "25"},
			{Field: "path", Operator: "starts_with", Value: "/checkout/"},
		},
		Actions: []Action{{Type: "tarpit"}},
	}}); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return rs
}

// rules-engine.feature « Règle basée sur le trust_score courant » : le score est
// lu dans le ScoreManager. Il était lu dans X-WAF-Score, que l'ingress supprime
// et que le middleware de score ne pose qu'en aval des règles : la condition
// était toujours fausse en production.
func TestTrustScoreConditionReadsTheScoreManager(t *testing.T) {
	scores := newScoreManager(t)
	scores.Set("1.2.3.4", "shop.example", 20)
	var action string

	NewMiddleware(lowTrustCheckoutRules(t), scores).Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		action = r.Header.Get("X-WAF-Action")
	})).ServeHTTP(httptest.NewRecorder(), request(http.MethodGet, "http://shop.example/checkout/payment", "1.2.3.4"))

	if action != "TARPIT" {
		t.Fatalf("X-WAF-Action = %q, want TARPIT for a visitor whose trust score is 20", action)
	}
}

func TestTrustScoreConditionIgnoresTheScoreHeader(t *testing.T) {
	scores := newScoreManager(t)
	scores.Set("1.2.3.4", "shop.example", 80)
	req := request(http.MethodGet, "http://shop.example/checkout/payment", "1.2.3.4")
	req.Header.Set("X-WAF-Score", "10")

	if actions := lowTrustCheckoutRules(t).Match(req, scores); len(actions) != 0 {
		t.Fatalf("actions = %v, want none: the visitor's score is 80, whatever X-WAF-Score says", actions)
	}
}

func TestTrustScoreConditionIsFalseWithoutScores(t *testing.T) {
	req := request(http.MethodGet, "http://shop.example/checkout/payment", "1.2.3.4")

	if actions := lowTrustCheckoutRules(t).Match(req, nil); len(actions) != 0 {
		t.Fatalf("actions = %v, want none when no score is known", actions)
	}
	NewMiddleware(lowTrustCheckoutRules(t), nil).Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(httptest.NewRecorder(), req)
}
