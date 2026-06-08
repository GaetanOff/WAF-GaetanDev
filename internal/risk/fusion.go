package risk

import "github.com/gaetandev/waf/internal/config"

type FusionConfig struct {
	Profile                      Profile
	Weights                      map[SignalFamily]float64
	FamilyCorroborationThreshold int
}

func DefaultFusionConfig(profile Profile) FusionConfig {
	cfg := FusionConfig{
		Profile: profile,
		Weights: map[SignalFamily]float64{
			FamilyReputation:  1.0,
			FamilyBehavioral:  1.0,
			FamilyTLS:         0.8,
			FamilyFingerprint: 1.0,
			FamilyIntegrity:   1.2,
			FamilyRate:        0.6,
			FamilyGeo:         0.5,
			FamilyHumanCredit: 1.0,
		},
		FamilyCorroborationThreshold: 50,
	}

	switch profile {
	case ProfileLenient:
		cfg.Weights[FamilyReputation] = 0.6
		cfg.Weights[FamilyBehavioral] = 0.7
		cfg.Weights[FamilyTLS] = 0.5
		cfg.Weights[FamilyFingerprint] = 0.7
		cfg.Weights[FamilyIntegrity] = 0.9
		cfg.Weights[FamilyRate] = 0.3
		cfg.Weights[FamilyGeo] = 0.2
		cfg.Weights[FamilyHumanCredit] = 3.0
		cfg.FamilyCorroborationThreshold = 60
	case ProfileStrict:
		cfg.Weights[FamilyReputation] = 1.8
		cfg.Weights[FamilyBehavioral] = 1.5
		cfg.Weights[FamilyTLS] = 1.2
		cfg.Weights[FamilyFingerprint] = 1.5
		cfg.Weights[FamilyIntegrity] = 1.6
		cfg.Weights[FamilyRate] = 1.0
		cfg.Weights[FamilyGeo] = 0.8
		cfg.Weights[FamilyHumanCredit] = 0.5
		cfg.FamilyCorroborationThreshold = 45
	default:
		cfg.Profile = ProfileBalanced
	}

	return cfg
}

func FusionConfigFromConfig(cfg config.RiskEngine) FusionConfig {
	fusion := DefaultFusionConfig(Profile(cfg.Profile))
	if cfg.FamilyCorroborationThreshold != 0 {
		fusion.FamilyCorroborationThreshold = cfg.FamilyCorroborationThreshold
	}
	for family, weight := range cfg.Weights {
		fusion.Weights[SignalFamily(family)] = weight
	}
	return fusion
}

func Fuse(contributions []Contribution, cfg FusionConfig) RiskAssessment {
	weights := cfg.Weights
	if len(weights) == 0 {
		weights = DefaultFusionConfig(cfg.Profile).Weights
	}

	totalWeight := totalConfiguredWeight(weights)
	if totalWeight == 0 {
		return NewAssessment(0, 0, DecisionAllow, contributions)
	}

	weightedRisk := 0.0
	availableWeight := 0.0
	factors := make([]Contribution, 0, len(contributions))
	for _, contribution := range contributions {
		weight := weights[contribution.Family]
		normalized := contribution
		normalized.Weight = weight
		normalized.Contribution = ClampContribution(normalized.Contribution)
		normalized.AboveThreshold = normalized.Contribution >= cfg.FamilyCorroborationThreshold

		if weight > 0 {
			weightedRisk += float64(normalized.Contribution) * weight
			if normalized.Signal != "" || normalized.Value != nil || normalized.Contribution != 0 {
				availableWeight += weight
			}
		}
		factors = append(factors, normalized)
	}

	score := round(weightedRisk / totalWeight)
	assessment := NewAssessment(score, availableWeight/totalWeight, DecisionAllow, factors)
	assessment.Profile = cfg.Profile
	return assessment
}

func totalConfiguredWeight(weights map[SignalFamily]float64) float64 {
	total := 0.0
	for _, family := range Families() {
		if weight := weights[family]; weight > 0 {
			total += weight
		}
	}
	return total
}

func round(value float64) int {
	if value < 0 {
		return int(value - 0.5)
	}
	return int(value + 0.5)
}
