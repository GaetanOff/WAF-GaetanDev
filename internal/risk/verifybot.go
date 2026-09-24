package risk

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/ttlcache"
)

const (
	crawlerSpoofContribution = 60
	// maxBotVerifications borne le cache des vérifications reverse-DNS.
	maxBotVerifications = 100000
	// verifyWorkers borne les vérifications DNS simultanées, verifyQueueSize
	// celles en attente ; dnsTimeout borne chaque résolution.
	verifyWorkers   = 8
	verifyQueueSize = 256
	dnsTimeout      = 2 * time.Second
)

type BotVerificationState string

const (
	BotVerificationNotCrawler BotVerificationState = "not_crawler"
	BotVerificationPending    BotVerificationState = "pending"
	BotVerificationVerified   BotVerificationState = "verified"
	BotVerificationSpoofed    BotVerificationState = "spoofed"
	// BotVerificationUnverified : crawler déclaré dont la vérification n'a pas
	// pu être planifiée (file saturée). Évalué comme un visiteur ordinaire,
	// sans le plafond OBSERVE de l'état pending : sinon saturer la file
	// suffirait à exempter un faux crawler de toute mitigation.
	BotVerificationUnverified BotVerificationState = "unverified"
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
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	return net.DefaultResolver.LookupAddr(ctx, addr)
}

func (netBotResolver) LookupHost(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	return net.DefaultResolver.LookupHost(ctx, host)
}

type BotVerifierConfig struct {
	Enabled         bool
	SuccessCacheTTL time.Duration
	FailureCacheTTL time.Duration
	Crawlers        []string
}

// BotVerifier vérifie par reverse-DNS confirmé qu'un crawler déclaré en est
// bien un (FR-36). Le cache des résultats est borné (maxBotVerifications, LRU)
// et expire selon success/failure_cache_ttl ; c'était une map dont les entrées
// périmées n'étaient jamais retirées.
type BotVerifier struct {
	resolver BotResolver
	cfg      BotVerifierConfig
	now      func() time.Time
	cache    *ttlcache.Cache[string, BotVerification]
	// jobs alimente un pool fixe de verifyWorkers goroutines. Une goroutine
	// par IP était lancée auparavant : un spoofing d'User-Agent crawler depuis
	// des milliers d'IP épuisait goroutines et sockets en résolutions DNS.
	jobs chan verifyJob

	mu       sync.Mutex
	inFlight map[string]bool
}

type verifyJob struct {
	key string
	ip  string
	bot string
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
	verifier := &BotVerifier{
		resolver: resolver,
		cfg:      cfg,
		now:      time.Now,
		inFlight: make(map[string]bool),
		jobs:     make(chan verifyJob, verifyQueueSize),
	}
	for range verifyWorkers {
		go verifier.worker()
	}
	verifier.cache = ttlcache.New[string, BotVerification](maxBotVerifications, cfg.FailureCacheTTL).WithClock(func() time.Time { return verifier.now() })
	return verifier
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
	if verification, ok := v.cache.Get(key); ok {
		return verification
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.inFlight[key] {
		return BotVerification{Bot: bot, State: BotVerificationPending}
	}
	select {
	case v.jobs <- verifyJob{key: key, ip: ip, bot: bot}:
		v.inFlight[key] = true
		return BotVerification{Bot: bot, State: BotVerificationPending}
	default:
		return BotVerification{Bot: bot, State: BotVerificationUnverified}
	}
}

// Close arrête les workers de vérification.
func (v *BotVerifier) Close() {
	close(v.jobs)
}

func (v *BotVerifier) worker() {
	for job := range v.jobs {
		v.verify(job.key, job.ip, job.bot)
	}
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

	v.cache.SetWithTTL(key, result, ttl)
	v.mu.Lock()
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
		if slices.Contains(addresses, ip) {
			return true
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
