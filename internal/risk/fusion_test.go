package risk

import (
	"math"
	"testing"

	"github.com/gaetandev/waf/internal/config"
)

func TestFuseComputesWeightedRiskScoreAndConfidence(t *testing.T) {
	cfg := DefaultFusionConfig(ProfileBalanced)
	contributions := CollectContributions([]SignalProvider{
		staticSignalProvider{
			family: FamilyReputation,
			contribution: Contribution{
				Signal:       "abuseipdb_score",
				Value:        80,
				Contribution: 80,
			},
		},
		staticSignalProvider{
			family: FamilyRate,
			contribution: Contribution{
				Signal:       "burst",
				Value:        true,
				Contribution: 50,
			},
		},
	})

	assessment := Fuse(contributions, cfg)

	if assessment.RiskScore != 15 {
		t.Fatalf("RiskScore = %d, want 15", assessment.RiskScore)
	}
	if math.Abs(assessment.Confidence-0.22535211267605634) > 0.0000000001 {
		t.Fatalf("Confidence = %v, want weighted availability ratio", assessment.Confidence)
	}
	if assessment.CorroboratingFamilies != 2 {
		t.Fatalf("CorroboratingFamilies = %d, want 2", assessment.CorroboratingFamilies)
	}
	if assessment.Profile != ProfileBalanced {
		t.Fatalf("Profile = %s, want %s", assessment.Profile, ProfileBalanced)
	}
}

func TestFuseIsDeterministic(t *testing.T) {
	cfg := DefaultFusionConfig(ProfileStrict)
	contributions := CollectContributions([]SignalProvider{
		staticSignalProvider{family: FamilyBehavioral, contribution: Contribution{Signal: "anomaly", Contribution: 70}},
		staticSignalProvider{family: FamilyFingerprint, contribution: Contribution{Signal: "headless", Contribution: 65}},
	})

	first := Fuse(contributions, cfg)
	second := Fuse(contributions, cfg)

	if first.RiskScore != second.RiskScore {
		t.Fatalf("RiskScore changed: first=%d second=%d", first.RiskScore, second.RiskScore)
	}
	if first.Confidence != second.Confidence {
		t.Fatalf("Confidence changed: first=%v second=%v", first.Confidence, second.Confidence)
	}
	if first.CorroboratingFamilies != second.CorroboratingFamilies {
		t.Fatalf("CorroboratingFamilies changed: first=%d second=%d", first.CorroboratingFamilies, second.CorroboratingFamilies)
	}
}

func TestFuseProfilesAdjustRiskScore(t *testing.T) {
	contributions := CollectContributions([]SignalProvider{
		staticSignalProvider{family: FamilyReputation, contribution: Contribution{Signal: "asn_datacenter", Contribution: 80}},
	})

	lenient := Fuse(contributions, DefaultFusionConfig(ProfileLenient))
	balanced := Fuse(contributions, DefaultFusionConfig(ProfileBalanced))
	strict := Fuse(contributions, DefaultFusionConfig(ProfileStrict))

	if !(lenient.RiskScore < balanced.RiskScore && balanced.RiskScore < strict.RiskScore) {
		t.Fatalf("profile scores not increasing by strictness: lenient=%d balanced=%d strict=%d", lenient.RiskScore, balanced.RiskScore, strict.RiskScore)
	}
}

func TestFuseAppliesHumanCreditAndClampsScore(t *testing.T) {
	cfg := DefaultFusionConfig(ProfileBalanced)
	contributions := CollectContributions([]SignalProvider{
		staticSignalProvider{family: FamilyIntegrity, contribution: Contribution{Signal: "path_obfuscation", Contribution: 100}},
		staticSignalProvider{family: FamilyHumanCredit, contribution: Contribution{Signal: "challenge_passed", Value: true, Contribution: -100}},
	})

	assessment := Fuse(contributions, cfg)

	if assessment.RiskScore != 3 {
		t.Fatalf("RiskScore = %d, want 3 after human credit", assessment.RiskScore)
	}
	if assessment.Factors[len(assessment.Factors)-1].Contribution != -100 {
		t.Fatalf("human credit contribution = %d, want -100", assessment.Factors[len(assessment.Factors)-1].Contribution)
	}
}

func TestFusionConfigFromConfigUsesRuntimeWeights(t *testing.T) {
	riskConfig := config.Default().RiskEngine
	riskConfig.Profile = string(ProfileBalanced)
	riskConfig.Weights["reputation"] = 2
	riskConfig.FamilyCorroborationThreshold = 70

	fusion := FusionConfigFromConfig(riskConfig)

	if fusion.Weights[FamilyReputation] != 2 {
		t.Fatalf("reputation weight = %v, want 2", fusion.Weights[FamilyReputation])
	}
	if fusion.FamilyCorroborationThreshold != 70 {
		t.Fatalf("FamilyCorroborationThreshold = %d, want 70", fusion.FamilyCorroborationThreshold)
	}
}
