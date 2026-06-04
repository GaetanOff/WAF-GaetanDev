package admin

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/middleware/access"
)

type IPEntry struct {
	IP      string `json:"ip"`
	AddedAt string `json:"added_at,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

type State struct {
	mu           sync.RWMutex
	cfg          config.Config
	accessRules  *access.RuleSet
	whitelist    map[string]IPEntry
	blacklist    map[string]IPEntry
	userAgents   []string
	recentEvents []SecurityEventSummary
	now          func() time.Time
}

func NewState(cfg config.Config, accessRules *access.RuleSet) (*State, error) {
	state := &State{
		cfg:          cfg,
		accessRules:  accessRules,
		whitelist:    make(map[string]IPEntry),
		blacklist:    make(map[string]IPEntry),
		userAgents:   append([]string(nil), cfg.WhitelistUserAgents...),
		recentEvents: []SecurityEventSummary{},
		now:          time.Now,
	}
	for _, ip := range cfg.Whitelist {
		normalized, err := normalizeIPRule(ip)
		if err != nil {
			return nil, err
		}
		state.whitelist[normalized] = IPEntry{IP: normalized}
	}
	for _, ip := range cfg.Blacklist {
		normalized, err := normalizeIPRule(ip)
		if err != nil {
			return nil, err
		}
		state.blacklist[normalized] = IPEntry{IP: normalized}
	}
	return state, nil
}

func (s *State) ListWhitelist() []IPEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sortedEntries(s.whitelist)
}

func (s *State) ListBlacklist() []IPEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sortedEntries(s.blacklist)
}

func (s *State) AddWhitelist(entry IPEntry) (IPEntry, bool, error) {
	return s.addEntry(s.whitelist, entry, true)
}

func (s *State) AddBlacklist(entry IPEntry) (IPEntry, bool, error) {
	return s.addEntry(s.blacklist, entry, false)
}

func (s *State) RemoveWhitelist(ip string) bool {
	return s.removeEntry(s.whitelist, ip)
}

func (s *State) RemoveBlacklist(ip string) bool {
	return s.removeEntry(s.blacklist, ip)
}

func (s *State) Config() config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sanitizedConfig(s.cfg)
}

func (s *State) Events() []SecurityEventSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	events := append([]SecurityEventSummary(nil), s.recentEvents...)
	return events
}

func (s *State) addEntry(target map[string]IPEntry, entry IPEntry, whitelist bool) (IPEntry, bool, error) {
	normalized, err := normalizeIPRule(entry.IP)
	if err != nil {
		return IPEntry{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := target[normalized]; exists {
		return IPEntry{}, true, nil
	}
	entry.IP = normalized
	entry.AddedAt = s.now().UTC().Format(time.RFC3339)
	target[normalized] = entry
	if whitelist {
		s.cfg.Whitelist = keys(s.whitelist)
	} else {
		s.cfg.Blacklist = keys(s.blacklist)
	}
	if err := s.syncAccessRulesLocked(); err != nil {
		delete(target, normalized)
		return IPEntry{}, false, err
	}
	return entry, false, nil
}

func (s *State) removeEntry(target map[string]IPEntry, ip string) bool {
	normalized, err := normalizeIPRule(ip)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := target[normalized]; !exists {
		return false
	}
	delete(target, normalized)
	s.cfg.Whitelist = keys(s.whitelist)
	s.cfg.Blacklist = keys(s.blacklist)
	_ = s.syncAccessRulesLocked()
	return true
}

func (s *State) syncAccessRulesLocked() error {
	if s.accessRules == nil {
		return nil
	}
	return s.accessRules.Update(keys(s.whitelist), keys(s.blacklist), s.userAgents)
}

func normalizeIPRule(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return "", err
		}
		return prefix.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}

func sortedEntries(entries map[string]IPEntry) []IPEntry {
	items := make([]IPEntry, 0, len(entries))
	for _, entry := range entries {
		items = append(items, entry)
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].IP < items[j].IP
	})
	return items
}

func keys(entries map[string]IPEntry) []string {
	values := make([]string, 0, len(entries))
	for key := range entries {
		values = append(values, key)
	}
	sort.Strings(values)
	return values
}

func sanitizedConfig(cfg config.Config) config.Config {
	if cfg.Challenge.SecretKey != "" {
		cfg.Challenge.SecretKey = "***"
	}
	if cfg.Admin.Token != "" {
		cfg.Admin.Token = "***"
	}
	if cfg.Storage.Redis != nil && cfg.Storage.Redis.Password != "" {
		cfg.Storage.Redis.Password = "***"
	}
	return cfg
}
