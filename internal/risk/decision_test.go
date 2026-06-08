package risk

import (
	"testing"

	"github.com/gaetandev/waf/internal/config"
)

func TestDecideMapsRiskScoreAndConfidenceToMitigationTier(t *testing.T) {
	cfg := DefaultDecisionConfig(ProfileBalanced)
	tests := []struct {
		name       string
		score      int
		confidence float64
		want       Decision
	}{
		{name: "allow", score: 5, confidence: 0.9, want: DecisionAllow},
		{name: "observe", score: 30, confidence: 0.8, want: DecisionObserve},
		{name: "throttle", score: 50, confidence: 0.8, want: DecisionThrottle},
		{name: "challenge", score: 70, confidence: 0.8, want: DecisionChallenge},
		{name: "block", score: 90, confidence: 0.9, want: DecisionBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decide(tt.score, tt.confidence, cfg); got != tt.want {
				t.Fatalf("Decide(%d, %v) = %s, want %s", tt.score, tt.confidence, got, tt.want)
			}
		})
	}
}

func TestDecideCapsLowConfidenceHardMitigationAtChallenge(t *testing.T) {
	cfg := DefaultDecisionConfig(ProfileBalanced)

	if got := Decide(85, 0.2, cfg); got != DecisionChallenge {
		t.Fatalf("Decide(85, 0.2) = %s, want CHALLENGE", got)
	}
	if got := Decide(95, 0.2, cfg); got != DecisionChallenge {
		t.Fatalf("Decide(95, 0.2) = %s, want CHALLENGE", got)
	}
}

func TestDecideUsesConfigurableTierBounds(t *testing.T) {
	cfg := DefaultDecisionConfig(ProfileBalanced)
	cfg.Tiers = DecisionTiers{
		Observe:   10,
		Throttle:  20,
		Challenge: 30,
		Tarpit:    40,
		Block:     50,
	}

	if got := Decide(50, 0.9, cfg); got != DecisionBlock {
		t.Fatalf("Decide(50, 0.9) = %s, want BLOCK", got)
	}
	if got := Decide(25, 0.9, cfg); got != DecisionThrottle {
		t.Fatalf("Decide(25, 0.9) = %s, want THROTTLE", got)
	}
}

func TestDecisionProfilesAdjustTierBounds(t *testing.T) {
	score := 88
	confidence := 0.9

	lenient := Decide(score, confidence, DefaultDecisionConfig(ProfileLenient))
	balanced := Decide(score, confidence, DefaultDecisionConfig(ProfileBalanced))
	strict := Decide(score, confidence, DefaultDecisionConfig(ProfileStrict))

	if lenient != DecisionTarpit {
		t.Fatalf("lenient decision = %s, want TARPIT", lenient)
	}
	if balanced != DecisionTarpit {
		t.Fatalf("balanced decision = %s, want TARPIT", balanced)
	}
	if strict != DecisionBlock {
		t.Fatalf("strict decision = %s, want BLOCK", strict)
	}
}

func TestDecisionConfigFromConfigUsesRuntimeTiers(t *testing.T) {
	riskConfig := config.Default().RiskEngine
	riskConfig.Profile = string(ProfileStrict)
	riskConfig.BlockMinConfidence = 0.7
	riskConfig.Tiers.Observe = 20
	riskConfig.Tiers.Throttle = 40
	riskConfig.Tiers.Challenge = 60
	riskConfig.Tiers.Tarpit = 75
	riskConfig.Tiers.Block = 95

	decision := DecisionConfigFromConfig(riskConfig)

	if decision.Profile != ProfileStrict {
		t.Fatalf("Profile = %s, want strict", decision.Profile)
	}
	if decision.BlockMinConfidence != 0.7 {
		t.Fatalf("BlockMinConfidence = %v, want 0.7", decision.BlockMinConfidence)
	}
	if got := Decide(90, 0.9, decision); got != DecisionTarpit {
		t.Fatalf("Decide(90, 0.9) = %s, want TARPIT", got)
	}
}

func TestApplyDecisionUpdatesAssessment(t *testing.T) {
	assessment := NewAssessment(50, 0.8, DecisionAllow, nil)

	updated := ApplyDecision(assessment, DefaultDecisionConfig(ProfileBalanced))

	if updated.Decision != DecisionThrottle {
		t.Fatalf("Decision = %s, want THROTTLE", updated.Decision)
	}
	if updated.DecisionBasis != DecisionBasisHeuristic {
		t.Fatalf("DecisionBasis = %s, want heuristic", updated.DecisionBasis)
	}
	if updated.Profile != ProfileBalanced {
		t.Fatalf("Profile = %s, want balanced", updated.Profile)
	}
}
