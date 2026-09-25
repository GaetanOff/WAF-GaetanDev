package risk

import (
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
)

func TestBotVerifierReturnsPendingThenVerifiedGooglebot(t *testing.T) {
	resolver := fakeBotResolver{
		names: map[string][]string{
			"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
		},
		hosts: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
		},
	}
	verifier := newTestBotVerifier(resolver)

	first := verifier.Check("66.249.66.1", "Mozilla/5.0 Googlebot/2.1")
	if first.State != BotVerificationPending {
		t.Fatalf("first state = %s, want pending", first.State)
	}

	second := waitForBotState(t, verifier, "66.249.66.1", "Mozilla/5.0 Googlebot/2.1", BotVerificationVerified)
	if second.Bot != "googlebot" {
		t.Fatalf("bot = %s, want googlebot", second.Bot)
	}
}

func TestApplyBotVerificationAllowsVerifiedCrawler(t *testing.T) {
	assessment := RiskAssessment{
		RiskScore:             95,
		Confidence:            0.9,
		Decision:              DecisionBlock,
		DecisionBasis:         DecisionBasisHeuristic,
		CorroboratingFamilies: 2,
	}

	updated := ApplyBotVerification(assessment, BotVerification{Bot: "googlebot", State: BotVerificationVerified})

	if updated.Decision != DecisionAllow {
		t.Fatalf("Decision = %s, want ALLOW", updated.Decision)
	}
	if updated.DecisionBasis != DecisionBasisVerifiedBot {
		t.Fatalf("DecisionBasis = %s, want verified_bot", updated.DecisionBasis)
	}
	if updated.VerifiedGoodBot == nil || *updated.VerifiedGoodBot != "googlebot" {
		t.Fatalf("VerifiedGoodBot = %v, want googlebot", updated.VerifiedGoodBot)
	}
}

func TestApplyBotVerificationKeepsDeterministicBlock(t *testing.T) {
	trigger := TriggerBlacklist
	bot := "googlebot"
	assessment := RiskAssessment{
		RiskScore:            95,
		Confidence:           0.9,
		Decision:             DecisionBlock,
		DecisionBasis:        DecisionBasisDeterministic,
		DeterministicTrigger: &trigger,
		VerifiedGoodBot:      &bot,
	}

	updated := ApplyBotVerification(assessment, BotVerification{Bot: "googlebot", State: BotVerificationVerified})

	if updated.Decision != DecisionBlock {
		t.Fatalf("Decision = %s, want BLOCK", updated.Decision)
	}
	if updated.DecisionBasis != DecisionBasisDeterministic {
		t.Fatalf("DecisionBasis = %s, want deterministic", updated.DecisionBasis)
	}
}

func TestApplyBotVerificationCapsPendingCrawlerAtObserve(t *testing.T) {
	assessment := RiskAssessment{
		RiskScore:     90,
		Confidence:    0.9,
		Decision:      DecisionBlock,
		DecisionBasis: DecisionBasisHeuristic,
	}

	updated := ApplyBotVerification(assessment, BotVerification{Bot: "googlebot", State: BotVerificationPending})

	if updated.Decision != DecisionObserve {
		t.Fatalf("Decision = %s, want OBSERVE", updated.Decision)
	}
}

func TestBotVerifierTreatsSpoofedGooglebotAsSuspect(t *testing.T) {
	resolver := fakeBotResolver{
		names: map[string][]string{
			"203.0.113.10": {"attacker.example.net."},
		},
		hosts: map[string][]string{
			"attacker.example.net": {"203.0.113.10"},
		},
	}
	verifier := newTestBotVerifier(resolver)

	_ = verifier.Check("203.0.113.10", "Googlebot")
	result := waitForBotState(t, verifier, "203.0.113.10", "Googlebot", BotVerificationSpoofed)
	contribution := BotVerificationContribution(result)

	if contribution.Family != FamilyReputation {
		t.Fatalf("Family = %s, want reputation", contribution.Family)
	}
	if contribution.Signal != "crawler_spoof" {
		t.Fatalf("Signal = %s, want crawler_spoof", contribution.Signal)
	}
	if contribution.Contribution != crawlerSpoofContribution {
		t.Fatalf("Contribution = %d, want %d", contribution.Contribution, crawlerSpoofContribution)
	}
	if !contribution.AboveThreshold {
		t.Fatal("AboveThreshold = false, want true")
	}
}

func TestBotVerifierConfigFromConfigParsesTTLs(t *testing.T) {
	cfg, err := BotVerifierConfigFromConfig(config.Default().RiskEngine.VerifiedBots)
	if err != nil {
		t.Fatalf("BotVerifierConfigFromConfig() error = %v", err)
	}

	if cfg.SuccessCacheTTL != 12*time.Hour {
		t.Fatalf("SuccessCacheTTL = %v, want 12h", cfg.SuccessCacheTTL)
	}
	if cfg.FailureCacheTTL != 10*time.Minute {
		t.Fatalf("FailureCacheTTL = %v, want 10m", cfg.FailureCacheTTL)
	}
}

func newTestBotVerifier(resolver fakeBotResolver) *BotVerifier {
	verifier := NewBotVerifier(BotVerifierConfig{
		Enabled:         true,
		SuccessCacheTTL: time.Hour,
		FailureCacheTTL: time.Minute,
		Crawlers:        []string{"googlebot", "bingbot", "duckduckbot", "applebot"},
	}, resolver)
	return verifier
}

func waitForBotState(t *testing.T, verifier *BotVerifier, ip string, userAgent string, state BotVerificationState) BotVerification {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		result := verifier.Check(ip, userAgent)
		if result.State == state {
			return result
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("bot verification did not reach state %s", state)
	return BotVerification{}
}

type fakeBotResolver struct {
	names map[string][]string
	hosts map[string][]string
}

func (r fakeBotResolver) LookupAddr(addr string) ([]string, error) {
	names, ok := r.names[addr]
	if !ok {
		return nil, errors.New("not found")
	}
	return names, nil
}

func (r fakeBotResolver) LookupHost(host string) ([]string, error) {
	addresses, ok := r.hosts[host]
	if !ok {
		return nil, errors.New("not found")
	}
	return addresses, nil
}

// Régression : le cache des vérifications était une map jamais purgée.
func TestBotVerifierCacheIsBounded(t *testing.T) {
	verifier := newTestBotVerifier(fakeBotResolver{})
	for i := range maxBotVerifications + 100 {
		verifier.verify(fmt.Sprintf("googlebot|10.0.%d", i), "10.0.0.1", "googlebot")
	}
	// Cache segmenté (ttlcache) : borné, un segment pouvant évincer avant que
	// les autres soient pleins.
	if got := verifier.cache.Len(); got > maxBotVerifications || got < maxBotVerifications*98/100 {
		t.Fatalf("cached verifications = %d, want at most %d and nearly full", got, maxBotVerifications)
	}
}

type blockingBotResolver struct {
	release chan struct{}
	active  *atomic.Int64
	peak    *atomic.Int64
}

func (r blockingBotResolver) LookupAddr(string) ([]string, error) {
	current := r.active.Add(1)
	for {
		peak := r.peak.Load()
		if current <= peak || r.peak.CompareAndSwap(peak, current) {
			break
		}
	}
	<-r.release
	r.active.Add(-1)
	return nil, errors.New("not found")
}

func (blockingBotResolver) LookupHost(string) ([]string, error) {
	return nil, errors.New("not found")
}

// Régression : chaque IP annonçant un User-Agent crawler lançait sa goroutine
// de résolution DNS. Les vérifications sont bornées ; au-delà de la file,
// l'IP est « unverified » — évaluée normalement, jamais exemptée.
func TestBotVerifierBoundsConcurrentVerifications(t *testing.T) {
	resolver := blockingBotResolver{release: make(chan struct{}), active: new(atomic.Int64), peak: new(atomic.Int64)}
	verifier := NewBotVerifier(BotVerifierConfig{Enabled: true, Crawlers: []string{"googlebot"}}, resolver)
	defer verifier.Close()
	before := runtime.NumGoroutine()

	unverified := 0
	for i := range 3000 {
		if verifier.Check(fmt.Sprintf("10.0.%d.%d", i>>8, i&0xff), "Googlebot").State == BotVerificationUnverified {
			unverified++
		}
	}
	time.Sleep(50 * time.Millisecond)

	if grown := runtime.NumGoroutine() - before; grown > 0 {
		t.Fatalf("goroutines grew by %d for 3000 spoofed crawlers, want none beyond the fixed pool", grown)
	}
	if peak := resolver.peak.Load(); peak > verifyWorkers {
		t.Fatalf("concurrent DNS verifications = %d, want <= %d", peak, verifyWorkers)
	}
	if unverified == 0 {
		t.Fatal("a saturated queue must answer unverified, not pending")
	}
	close(resolver.release)
}

func TestApplyBotVerificationDoesNotCapUnverifiedCrawler(t *testing.T) {
	assessment := RiskAssessment{RiskScore: 90, Confidence: 0.9, Decision: DecisionBlock, DecisionBasis: DecisionBasisHeuristic}
	updated := ApplyBotVerification(assessment, BotVerification{Bot: "googlebot", State: BotVerificationUnverified})
	if updated.Decision != DecisionBlock {
		t.Fatalf("Decision = %s, want BLOCK unchanged for an unverified crawler", updated.Decision)
	}
}

// Le middleware construit son vérificateur (8 workers) et n'exposait aucun
// moyen de l'arrêter : Close les libère, et reste sûr en double appel comme
// face à un Check postérieur.
func TestMiddlewareCloseStopsBotVerifierWorkers(t *testing.T) {
	before := runtime.NumGoroutine()
	verifier := NewBotVerifier(BotVerifierConfig{Enabled: true, Crawlers: []string{"googlebot"}}, nil)
	middleware := NewMiddlewareWithVerifier(nil, FusionConfig{}, DecisionConfig{}, nil, verifier, false)

	middleware.Close()
	middleware.Close()

	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if grown := runtime.NumGoroutine() - before; grown > 0 {
		t.Fatalf("%d verifier goroutines still running after Close", grown)
	}
	if state := verifier.Check("66.249.66.1", "Googlebot").State; state != BotVerificationUnverified {
		t.Fatalf("state after Close = %q, want unverified", state)
	}
}
