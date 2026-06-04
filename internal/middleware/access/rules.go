package access

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
)

type RuleSet struct {
	mu sync.RWMutex

	whitelist  RuleMatcher
	blacklist  RuleMatcher
	userAgents []*regexp.Regexp
}

type RuleMatcher struct {
	exact map[netip.Addr]struct{}
	cidrs []netip.Prefix
}

func NewRuleSet(whitelist []string, blacklist []string, userAgents []string) (*RuleSet, error) {
	rules := &RuleSet{}
	if err := rules.Update(whitelist, blacklist, userAgents); err != nil {
		return nil, err
	}
	return rules, nil
}

func (r *RuleSet) Update(whitelist []string, blacklist []string, userAgents []string) error {
	nextWhitelist, err := compileIPRules(whitelist)
	if err != nil {
		return fmt.Errorf("compile whitelist: %w", err)
	}
	nextBlacklist, err := compileIPRules(blacklist)
	if err != nil {
		return fmt.Errorf("compile blacklist: %w", err)
	}
	nextUserAgents, err := compileUserAgents(userAgents)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.whitelist = nextWhitelist
	r.blacklist = nextBlacklist
	r.userAgents = nextUserAgents

	return nil
}

func (r *RuleSet) IsWhitelisted(ip string, userAgent string) (bool, string) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false, ""
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if reason := r.whitelist.match(addr); reason != "" {
		return true, "whitelist_" + reason
	}
	for _, pattern := range r.userAgents {
		if pattern.MatchString(userAgent) {
			return true, "whitelist_user_agent"
		}
	}

	return false, ""
}

func (r *RuleSet) IsBlacklisted(ip string) (bool, string) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false, ""
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if reason := r.blacklist.match(addr); reason != "" {
		return true, "blacklist_" + reason
	}

	return false, ""
}

func compileIPRules(values []string) (RuleMatcher, error) {
	matcher := RuleMatcher{exact: make(map[netip.Addr]struct{})}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.Contains(value, "/") {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return matcher, err
			}
			matcher.cidrs = append(matcher.cidrs, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return matcher, err
		}
		matcher.exact[addr] = struct{}{}
	}
	return matcher, nil
}

func compileUserAgents(values []string) ([]*regexp.Regexp, error) {
	patterns := make([]*regexp.Regexp, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		pattern, err := regexp.Compile(value)
		if err != nil {
			return nil, fmt.Errorf("compile user-agent pattern %q: %w", value, err)
		}
		patterns = append(patterns, pattern)
	}
	return patterns, nil
}

func (m RuleMatcher) match(addr netip.Addr) string {
	if _, ok := m.exact[addr]; ok {
		return "exact"
	}
	for _, cidr := range m.cidrs {
		if cidr.Contains(addr) {
			return "cidr"
		}
	}
	return ""
}
