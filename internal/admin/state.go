package admin

import (
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/middleware/access"
)

// clusterBlacklistReason marque les entrées de blacklist reçues d'un autre nœud.
const clusterBlacklistReason = "cluster_sync"

// maskedSecret remplace un secret dans GET /waf/admin/config (admin.openapi.yaml).
const maskedSecret = "***"

type IPEntry struct {
	IP      string `json:"ip"`
	AddedAt string `json:"added_at,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

type State struct {
	mu          sync.RWMutex
	cfg         config.Config
	accessRules *access.RuleSet
	whitelist   map[string]IPEntry
	blacklist   map[string]IPEntry
	userAgents  []string
	now         func() time.Time
}

func NewState(cfg config.Config, accessRules *access.RuleSet) (*State, error) {
	state := &State{
		cfg:         cfg,
		accessRules: accessRules,
		whitelist:   make(map[string]IPEntry),
		blacklist:   make(map[string]IPEntry),
		userAgents:  append([]string(nil), cfg.WhitelistUserAgents...),
		now:         time.Now,
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

// ApplyConfigUpdate reporte update sur la configuration courante, valide la
// configuration entière (mêmes règles qu'au démarrage) et, si elle l'est, la
// retient. Retourne la configuration résultante et les champs modifiés.
func (s *State) ApplyConfigUpdate(update ConfigUpdate) (config.Config, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cfg
	fields := update.applyTo(&next)
	if err := next.Validate(); err != nil {
		return config.Config{}, nil, err
	}
	s.cfg = next
	return next, fields, nil
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

// sanitizedConfig masque les secrets exposés par GET /waf/admin/config. Le
// secret HMAC de l'origine et la clé AbuseIPDB étaient rendus en clair : un
// lecteur de l'API admin pouvait forger X-WAF-Origin-Token et joindre l'origine
// sans passer par le WAF. Une URL de webhook porte son jeton d'accès.
//
// cfg est une copie, mais Storage.Redis et Alerting.Webhooks sont partagés avec
// la configuration active : ils sont copiés avant masquage, sans quoi le
// premier GET écrasait le mot de passe Redis de la configuration en vigueur.
func sanitizedConfig(cfg config.Config) config.Config {
	mask(&cfg.Challenge.SecretKey)
	mask(&cfg.Admin.Token)
	mask(&cfg.OriginProtection.Secret)
	mask(&cfg.ThreatIntel.AbuseIPDB.APIKey)
	if cfg.Storage.Redis != nil {
		redis := *cfg.Storage.Redis
		mask(&redis.Password)
		cfg.Storage.Redis = &redis
	}
	webhooks := slices.Clone(cfg.Alerting.Webhooks)
	for i := range webhooks {
		mask(&webhooks[i].URL)
	}
	cfg.Alerting.Webhooks = webhooks
	return cfg
}

func mask(secret *string) {
	if *secret != "" {
		*secret = maskedSecret
	}
}
