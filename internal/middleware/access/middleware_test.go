package access

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gaetandev/waf/internal/middleware/cloudflare"
)

func TestWhitelistCIDRPassesThrough(t *testing.T) {
	rules := newRules(t, []string{"192.168.1.0/24"}, nil, nil)
	request := requestFrom("192.168.1.100:1234")
	response := httptest.NewRecorder()

	Middleware(rules, okHandler()).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
	if got := request.Header.Get("X-WAF-Reason"); got != "whitelist_cidr" {
		t.Fatalf("X-WAF-Reason = %q, want whitelist_cidr", got)
	}
}

func TestExactWhitelistPassesThrough(t *testing.T) {
	rules := newRules(t, []string{"203.0.113.42"}, nil, nil)
	request := requestFrom("203.0.113.42:1234")
	response := httptest.NewRecorder()

	Middleware(rules, okHandler()).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}

func TestExactBlacklistBlocks(t *testing.T) {
	rules := newRules(t, nil, []string{"10.0.0.5"}, nil)
	request := requestFrom("10.0.0.5:1234")
	response := httptest.NewRecorder()

	Middleware(rules, okHandler()).ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if got := response.Header().Get("X-WAF-Reason"); got != "blacklist_exact" {
		t.Fatalf("X-WAF-Reason = %q, want blacklist_exact", got)
	}
}

func TestCIDRBlacklistBlocks(t *testing.T) {
	rules := newRules(t, nil, []string{"198.51.100.0/24"}, nil)
	request := requestFrom("198.51.100.150:1234")
	response := httptest.NewRecorder()

	Middleware(rules, okHandler()).ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestWhitelistHasPriorityOverBlacklist(t *testing.T) {
	rules := newRules(t, []string{"172.16.0.1"}, []string{"172.16.0.1"}, nil)
	request := requestFrom("172.16.0.1:1234")
	response := httptest.NewRecorder()

	Middleware(rules, okHandler()).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}

func TestWhitelistedUserAgentPassesThrough(t *testing.T) {
	rules := newRules(t, nil, nil, []string{"Googlebot"})
	request := requestFrom("203.0.113.10:1234")
	request.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1)")
	response := httptest.NewRecorder()

	Middleware(rules, okHandler()).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}

func TestRuleSetUpdateAppliesWithoutRestart(t *testing.T) {
	rules := newRules(t, nil, nil, nil)
	if err := rules.Update(nil, []string{"7.7.7.7"}, nil); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	request := requestFrom("7.7.7.7:1234")
	response := httptest.NewRecorder()

	Middleware(rules, okHandler()).ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func newRules(t *testing.T, whitelist []string, blacklist []string, userAgents []string) *RuleSet {
	t.Helper()

	rules, err := NewRuleSet(whitelist, blacklist, userAgents)
	if err != nil {
		t.Fatalf("NewRuleSet() error = %v", err)
	}
	return rules
}

func requestFrom(remoteAddr string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = remoteAddr
	return request
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
		_ = cloudflare.RealIP(r)
	})
}
