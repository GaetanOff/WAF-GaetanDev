package rules

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
