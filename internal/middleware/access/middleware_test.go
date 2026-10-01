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

func TestBlacklistSetsDeterministicTrigger(t *testing.T) {
	rules := newRules(t, nil, []string{"10.0.0.5"}, nil)
	request := requestFrom("10.0.0.5:1234")
	response := httptest.NewRecorder()

	Middleware(rules, okHandler()).ServeHTTP(response, request)

	if got := response.Header().Get("X-WAF-Deterministic-Trigger"); got != "blacklist" {
		t.Fatalf("X-WAF-Deterministic-Trigger = %q, want blacklist", got)
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

// FR-04 : une IPv4 mappée en IPv6 a le verdict de l'IPv4, que l'entrée de
// liste soit une IPv4, un CIDR IPv4 ou un CIDR IPv4 mappé.
func TestIPv4MappedAddressMatchesIPv4Entries(t *testing.T) {
	tests := []struct {
		name       string
		blacklist  string
		remoteAddr string
		wantReason string
	}{
		{name: "mapped client, exact IPv4 entry", blacklist: "198.51.100.5", remoteAddr: "[::ffff:198.51.100.5]:1234", wantReason: "blacklist_exact"},
		{name: "mapped client, IPv4 CIDR", blacklist: "198.51.100.0/24", remoteAddr: "[::ffff:198.51.100.150]:1234", wantReason: "blacklist_cidr"},
		{name: "IPv4 client, mapped entry", blacklist: "::ffff:198.51.100.5", remoteAddr: "198.51.100.5:1234", wantReason: "blacklist_exact"},
		{name: "IPv4 client, mapped CIDR", blacklist: "::ffff:198.51.100.0/120", remoteAddr: "198.51.100.150:1234", wantReason: "blacklist_cidr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := newRules(t, nil, []string{tt.blacklist}, nil)
			response := httptest.NewRecorder()

			Middleware(rules, okHandler()).ServeHTTP(response, requestFrom(tt.remoteAddr))

			if response.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", response.Code)
			}
			if got := response.Header().Get("X-WAF-Reason"); got != tt.wantReason {
				t.Fatalf("X-WAF-Reason = %q, want %q", got, tt.wantReason)
			}
		})
	}
	if ok, _ := newRules(t, []string{"198.51.100.0/24"}, nil, nil).IsWhitelisted("::ffff:198.51.100.7"); !ok {
		t.Fatal("::ffff:198.51.100.7 must match the whitelisted CIDR 198.51.100.0/24")
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

// Un User-Agent se forge : la whitelist UA n'est pas un bypass. La requête est
// seulement marquée (exemption du challenge proactif) et n'est pas PASS.
func TestWhitelistedUserAgentIsMarkedNotPassed(t *testing.T) {
	rules := newRules(t, nil, nil, []string{"Googlebot"})
	request := requestFrom("203.0.113.10:1234")
	request.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1)")
	response := httptest.NewRecorder()

	Middleware(rules, okHandler()).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
	if got := request.Header.Get("X-WAF-Action"); got == "PASS" {
		t.Fatal("whitelisted User-Agent must not bypass the pipeline with PASS")
	}
	if got := request.Header.Get(HeaderUserAgentWhitelisted); got != "true" {
		t.Fatalf("%s = %q, want true", HeaderUserAgentWhitelisted, got)
	}
}

func TestWhitelistedUserAgentDoesNotEscapeBlacklist(t *testing.T) {
	rules := newRules(t, nil, []string{"203.0.113.10"}, []string{"Googlebot"})
	request := requestFrom("203.0.113.10:1234")
	request.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1)")
	response := httptest.NewRecorder()

	Middleware(rules, okHandler()).ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: a blacklisted IP stays blocked whatever its User-Agent", response.Code)
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
