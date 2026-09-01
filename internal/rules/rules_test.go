package rules

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gaetandev/waf/internal/middleware/cloudflare"
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

	actions := rs.Match(request(http.MethodGet, "http://x/admin/users", "1.2.3.4"))
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

	if a := rs.Match(request(http.MethodPost, "http://x/", "10.1.2.3")); len(a) != 1 {
		t.Fatalf("expected match for 10.1.2.3 POST, got %+v", a)
	}
	if a := rs.Match(request(http.MethodGet, "http://x/", "10.1.2.3")); len(a) != 0 {
		t.Fatalf("GET must not match POST rule, got %+v", a)
	}
	if a := rs.Match(request(http.MethodPost, "http://x/", "8.8.8.8")); len(a) != 0 {
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
	if a := rs.Match(request(http.MethodGet, "http://x/x", "1.1.1.1")); len(a) != 0 {
		t.Fatalf("disabled rule must not match, got %+v", a)
	}

	// Hot-reload : on installe une règle active.
	_ = rs.Load([]Rule{{
		Name: "active", Priority: 1, Enabled: true,
		Conditions: []Condition{{Field: "path", Operator: "equals", Value: "/x"}},
		Actions:    []Action{{Type: "block"}},
	}})
	if a := rs.Match(request(http.MethodGet, "http://x/x", "1.1.1.1")); len(a) != 1 {
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

			matched := len(rs.Match(r)) == 1
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
		matched = len(rs.Match(inner)) == 1
	})).ServeHTTP(httptest.NewRecorder(), r)

	if !matched {
		t.Fatal("la règle doit matcher sur l'IP de CF-Connecting-IP validée, pas sur l'IP de l'edge Cloudflare")
	}
}
