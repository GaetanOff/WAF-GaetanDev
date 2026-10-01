package access

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
)

// ipv4MappedPrefixBits est la longueur du préfixe ::ffff:0:0/96 qui porte une
// IPv4 mappée en IPv6.
const ipv4MappedPrefixBits = 96

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

// AddBlacklist ajoute une IP ou un CIDR à la blacklist sans remplacer le jeu
// existant (utilisé pour appliquer une propagation cluster, FR-20). Idempotent.
func (r *RuleSet) AddBlacklist(value string) error {
	matcher, err := compileIPRules([]string{value})
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.blacklist.exact == nil {
		r.blacklist.exact = make(map[netip.Addr]struct{})
	}
	for addr := range matcher.exact {
		r.blacklist.exact[addr] = struct{}{}
	}
	r.blacklist.cidrs = append(r.blacklist.cidrs, matcher.cidrs...)
	return nil
}

// IsWhitelisted indique si l'IP est en whitelist (bypass total des protections,
// hors blacklist d'une autre entrée : la whitelist IP a priorité).
func (r *RuleSet) IsWhitelisted(ip string) (bool, string) {
	addr, err := parseAddr(ip)
	if err != nil {
		return false, ""
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if reason := r.whitelist.match(addr); reason != "" {
		return true, "whitelist_" + reason
	}
	return false, ""
}

// MatchesUserAgent indique si le User-Agent correspond à whitelist_user_agents.
// Contrairement à la whitelist IP, ce n'est PAS un bypass : un User-Agent se
// forge, il n'exempte que du challenge JS proactif.
func (r *RuleSet) MatchesUserAgent(userAgent string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, pattern := range r.userAgents {
		if pattern.MatchString(userAgent) {
			return true
		}
	}
	return false
}

func (r *RuleSet) IsBlacklisted(ip string) (bool, string) {
	addr, err := parseAddr(ip)
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
			prefix, err := parsePrefix(value)
			if err != nil {
				return matcher, err
			}
			matcher.cidrs = append(matcher.cidrs, prefix)
			continue
		}
		addr, err := parseAddr(value)
		if err != nil {
			return matcher, err
		}
		matcher.exact[addr] = struct{}{}
	}
	return matcher, nil
}

// parseAddr ramène une IPv4 mappée (::ffff:a.b.c.d) à l'IPv4 et retire la
// zone (FR-04) : sans cela, « ::ffff:198.51.100.5 » échappait à l'entrée
// « 198.51.100.5 » comme au CIDR « 198.51.100.0/24 ».
func parseAddr(value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr.Unmap().WithZone(""), nil
}

// parsePrefix masque le CIDR et ramène un préfixe IPv4 mappé
// (::ffff:198.51.100.0/120) au préfixe IPv4 équivalent (198.51.100.0/24), que
// parseAddr fait correspondre aux adresses démappées.
func parsePrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr := prefix.Addr(); addr.Is4In6() && prefix.Bits() >= ipv4MappedPrefixBits {
		prefix = netip.PrefixFrom(addr.Unmap(), prefix.Bits()-ipv4MappedPrefixBits)
	}
	return prefix.Masked(), nil
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
