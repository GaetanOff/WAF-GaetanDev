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

	if lenient.RiskScore >= balanced.RiskScore || balanced.RiskScore >= strict.RiskScore {
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
	riskConfig.Weights = map[string]float64{"reputation": 2}
	riskConfig.FamilyCorroborationThreshold = 70

	fusion := FusionConfigFromConfig(riskConfig)

	if fusion.Weights[FamilyReputation] != 2 {
		t.Fatalf("reputation weight = %v, want 2", fusion.Weights[FamilyReputation])
	}
	if fusion.Weights[FamilyIntegrity] != 1.2 {
		t.Fatalf("integrity weight = %v, want the balanced 1.2", fusion.Weights[FamilyIntegrity])
	}
	if fusion.FamilyCorroborationThreshold != 70 {
		t.Fatalf("FamilyCorroborationThreshold = %d, want 70", fusion.FamilyCorroborationThreshold)
	}
}

// FR-33 : sans surcharge, le profil s'applique. config.Default() pré-remplissait
// poids et paliers avec balanced, et profile: strict était inerte.
func TestProfileAppliesWithoutExplicitOverrides(t *testing.T) {
	riskConfig := config.Default().RiskEngine
	riskConfig.Profile = string(ProfileStrict)

	fusion := FusionConfigFromConfig(riskConfig)
	decision := DecisionConfigFromConfig(riskConfig)

	if fusion.Weights[FamilyReputation] != 1.8 || fusion.FamilyCorroborationThreshold != 45 {
		t.Fatalf("strict fusion = reputation %v, threshold %d; want 1.8 and 45", fusion.Weights[FamilyReputation], fusion.FamilyCorroborationThreshold)
	}
	if decision.Tiers != (DecisionTiers{Observe: 15, Throttle: 35, Challenge: 55, Tarpit: 72, Block: 85}) || decision.BlockMinConfidence != 0.5 {
		t.Fatalf("strict decision = %+v, block_min_confidence %v", decision.Tiers, decision.BlockMinConfidence)
	}

	riskConfig.Tiers.Block = 95
	if tiers := DecisionConfigFromConfig(riskConfig).Tiers; tiers.Block != 95 || tiers.Tarpit != 72 {
		t.Fatalf("explicit block tier: tiers = %+v, want block 95 and the strict tarpit 72", tiers)
	}
}

// risk-scoring-engine.feature, « Fusion et profils » : valeurs des scénarios.
func TestFusionModes(t *testing.T) {
	signal := func(family SignalFamily, contribution int) Contribution {
		return Contribution{Family: family, Signal: string(family), Contribution: contribution}
	}
	reputation := func(trustScore int, cfg FusionConfig) Contribution {
		return signal(FamilyReputation, reputationContribution(trustScore, cfg))
	}
	diluted := DefaultFusionConfig(ProfileBalanced)
	available := DefaultFusionConfig(ProfileBalanced)
	available.Mode = FusionAvailable
	available.InitialTrustScore = 50

	all := []Contribution{signal(FamilyReputation, 100)}
	for _, family := range []SignalFamily{FamilyBehavioral, FamilyTLS, FamilyFingerprint, FamilyIntegrity, FamilyRate, FamilyGeo} {
		all = append(all, signal(family, 100))
	}
	if got := Fuse(all, diluted).RiskScore; got != 86 {
		t.Errorf("diluted, seven families at 100: score = %d, want 86", got)
	}

	if got := Fuse([]Contribution{reputation(50, available)}, available); got.RiskScore != 0 {
		t.Errorf("available, new visitor: score = %d, want 0", got.RiskScore)
	}

	scanner := []Contribution{reputation(30, available), signal(FamilyIntegrity, 100), signal(FamilyRate, 80)}
	if scanner[0].Contribution != 40 {
		t.Fatalf("available reputation at 30 = %d, want 40", scanner[0].Contribution)
	}
	assessment := ApplyDecision(Fuse(scanner, available), DefaultDecisionConfig(ProfileBalanced))
	if assessment.RiskScore != 74 || assessment.Decision != DecisionChallenge {
		t.Errorf("available scanner: score %d, decision %s; want 74 CHALLENGE", assessment.RiskScore, assessment.Decision)
	}

	bot := []Contribution{
		reputation(0, available), signal(FamilyBehavioral, 90), signal(FamilyFingerprint, 90),
		signal(FamilyTLS, 80), signal(FamilyIntegrity, 100),
	}
	assessment = ApplyDecision(Fuse(bot, available), DefaultDecisionConfig(ProfileBalanced))
	if assessment.RiskScore != 93 || assessment.Confidence < 0.6 || assessment.Decision != DecisionBlock || assessment.DecisionBasis != DecisionBasisHeuristic {
		t.Errorf("available corroborated bot: score %d, confidence %.2f, decision %s (%s); want 93 >= 0.6 BLOCK heuristic", assessment.RiskScore, assessment.Confidence, assessment.Decision, assessment.DecisionBasis)
	}

	if got := reputationContribution(30, diluted); got != 70 {
		t.Errorf("diluted reputation at 30 = %d, want 70 (100 - score)", got)
	}
}
