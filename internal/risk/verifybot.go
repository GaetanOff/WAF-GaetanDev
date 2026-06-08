package risk

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gaetandev/waf/internal/config"
)

const crawlerSpoofContribution = 60

type BotVerificationState string

const (
	BotVerificationNotCrawler BotVerificationState = "not_crawler"
	BotVerificationPending    BotVerificationState = "pending"
	BotVerificationVerified   BotVerificationState = "verified"
	BotVerificationSpoofed    BotVerificationState = "spoofed"
)

type BotVerification struct {
	Bot   string
	State BotVerificationState
}

type BotResolver interface {
	LookupAddr(addr string) ([]string, error)
	LookupHost(host string) ([]string, error)
}

type netBotResolver struct{}

func (netBotResolver) LookupAddr(addr string) ([]string, error) {
	return net.LookupAddr(addr)
}

func (netBotResolver) LookupHost(host string) ([]string, error) {
	return net.LookupHost(host)
}

type BotVerifierConfig struct {
	Enabled         bool
	SuccessCacheTTL time.Duration
	FailureCacheTTL time.Duration
	Crawlers        []string
}

type BotVerifier struct {
	resolver BotResolver
	cfg      BotVerifierConfig
	now      func() time.Time

	mu       sync.Mutex
	cache    map[string]botCacheEntry
	inFlight map[string]bool
}

type botCacheEntry struct {
	verification BotVerification
	expiresAt    time.Time
}

func DefaultBotVerifierConfig() BotVerifierConfig {
	return BotVerifierConfig{
		Enabled:         true,
		SuccessCacheTTL: 12 * time.Hour,
		FailureCacheTTL: 10 * time.Minute,
		Crawlers:        []string{"googlebot", "bingbot", "duckduckbot", "applebot"},
	}
}

func BotVerifierConfigFromConfig(cfg config.VerifiedBots) (BotVerifierConfig, error) {
	successTTL, err := time.ParseDuration(cfg.SuccessCacheTTL)
	if err != nil {
		return BotVerifierConfig{}, err
	}
	failureTTL, err := time.ParseDuration(cfg.FailureCacheTTL)
	if err != nil {
		return BotVerifierConfig{}, err
	}
	return BotVerifierConfig{
		Enabled:         cfg.Enabled,
		SuccessCacheTTL: successTTL,
		FailureCacheTTL: failureTTL,
		Crawlers:        cfg.Crawlers,
	}, nil
}

func NewBotVerifier(cfg BotVerifierConfig, resolver BotResolver) *BotVerifier {
	if resolver == nil {
		resolver = netBotResolver{}
	}
	if cfg.SuccessCacheTTL == 0 {
		cfg.SuccessCacheTTL = 12 * time.Hour
	}
	if cfg.FailureCacheTTL == 0 {
		cfg.FailureCacheTTL = 10 * time.Minute
	}
	return &BotVerifier{
		resolver: resolver,
		cfg:      cfg,
		now:      time.Now,
		cache:    make(map[string]botCacheEntry),
		inFlight: make(map[string]bool),
	}
}

func (v *BotVerifier) Check(ip string, userAgent string) BotVerification {
	if !v.cfg.Enabled {
		return BotVerification{State: BotVerificationNotCrawler}
	}

	bot, ok := declaredCrawler(userAgent, v.cfg.Crawlers)
	if !ok {
		return BotVerification{State: BotVerificationNotCrawler}
	}

	key := bot + "|" + ip
	now := v.now()
	v.mu.Lock()
	if entry, ok := v.cache[key]; ok && entry.expiresAt.After(now) {
		v.mu.Unlock()
		return entry.verification
	}
	if !v.inFlight[key] {
		v.inFlight[key] = true
		go v.verify(key, ip, bot)
	}
	v.mu.Unlock()

	return BotVerification{Bot: bot, State: BotVerificationPending}
}

func (v *BotVerifier) verify(key string, ip string, bot string) {
	result := BotVerification{Bot: bot, State: BotVerificationSpoofed}
	if v.verifyForwardConfirmed(ip, bot) {
		result.State = BotVerificationVerified
	}

	ttl := v.cfg.FailureCacheTTL
	if result.State == BotVerificationVerified {
		ttl = v.cfg.SuccessCacheTTL
	}

	v.mu.Lock()
	v.cache[key] = botCacheEntry{
		verification: result,
		expiresAt:    v.now().Add(ttl),
	}
	delete(v.inFlight, key)
	v.mu.Unlock()
}

func (v *BotVerifier) verifyForwardConfirmed(ip string, bot string) bool {
	names, err := v.resolver.LookupAddr(ip)
	if err != nil {
		return false
	}
	for _, name := range names {
		host := strings.TrimSuffix(strings.ToLower(name), ".")
		if !crawlerHostMatches(bot, host) {
			continue
		}
		addresses, err := v.resolver.LookupHost(host)
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if address == ip {
				return true
			}
		}
	}
	return false
}

func ApplyBotVerification(assessment RiskAssessment, verification BotVerification) RiskAssessment {
	if assessment.DeterministicTrigger != nil {
		return assessment
	}

	switch verification.State {
	case BotVerificationVerified:
		bot := verification.Bot
		assessment.Decision = DecisionAllow
		assessment.DecisionBasis = DecisionBasisVerifiedBot
		assessment.VerifiedGoodBot = &bot
	case BotVerificationPending:
		if severity(assessment.Decision) > severity(DecisionObserve) {
			assessment.Decision = DecisionObserve
		}
	case BotVerificationSpoofed:
		assessment.VerifiedGoodBot = nil
	}
	return assessment
}

func BotVerificationContribution(verification BotVerification) Contribution {
	if verification.State != BotVerificationSpoofed {
		return NeutralContribution(FamilyReputation)
	}
	return Contribution{
		Family:         FamilyReputation,
		Signal:         "crawler_spoof",
		Value:          verification.Bot,
		Contribution:   crawlerSpoofContribution,
		AboveThreshold: true,
	}
}

func declaredCrawler(userAgent string, crawlers []string) (string, bool) {
	normalizedUA := strings.ToLower(userAgent)
	for _, crawler := range crawlers {
		normalizedCrawler := strings.ToLower(strings.TrimSpace(crawler))
		if normalizedCrawler != "" && strings.Contains(normalizedUA, normalizedCrawler) {
			return normalizedCrawler, true
		}
	}
	return "", false
}

func crawlerHostMatches(bot string, host string) bool {
	switch bot {
	case "googlebot":
		return strings.HasSuffix(host, ".googlebot.com") || strings.HasSuffix(host, ".google.com")
	case "bingbot":
		return strings.HasSuffix(host, ".search.msn.com")
	case "duckduckbot":
		return strings.HasSuffix(host, ".duckduckgo.com")
	case "applebot":
		return strings.HasSuffix(host, ".applebot.apple.com")
	default:
		return false
	}
}
