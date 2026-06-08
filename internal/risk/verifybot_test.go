package risk

import (
	"errors"
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
