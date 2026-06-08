package risk

import "github.com/gaetandev/waf/internal/config"

type DecisionConfig struct {
	Profile                  Profile
	BlockMinConfidence       float64
	MinCorroboratingFamilies int
	Tiers                    DecisionTiers
}

type DecisionTiers struct {
	Observe   int
	Throttle  int
	Challenge int
	Tarpit    int
	Block     int
}

func DefaultDecisionConfig(profile Profile) DecisionConfig {
	cfg := DecisionConfig{
		Profile:                  profile,
		BlockMinConfidence:       0.6,
		MinCorroboratingFamilies: 2,
		Tiers: DecisionTiers{
			Observe:   25,
			Throttle:  45,
			Challenge: 65,
			Tarpit:    80,
			Block:     90,
		},
	}

	switch profile {
	case ProfileLenient:
		cfg.BlockMinConfidence = 0.75
		cfg.Tiers = DecisionTiers{
			Observe:   35,
			Throttle:  55,
			Challenge: 75,
			Tarpit:    88,
			Block:     96,
		}
	case ProfileStrict:
		cfg.BlockMinConfidence = 0.5
		cfg.Tiers = DecisionTiers{
			Observe:   15,
			Throttle:  35,
			Challenge: 55,
			Tarpit:    72,
			Block:     85,
		}
	default:
		cfg.Profile = ProfileBalanced
	}

	return cfg
}

func DecisionConfigFromConfig(cfg config.RiskEngine) DecisionConfig {
	decision := DefaultDecisionConfig(Profile(cfg.Profile))
	decision.BlockMinConfidence = cfg.BlockMinConfidence
	decision.MinCorroboratingFamilies = cfg.MinCorroboratingFamilies
	decision.Tiers = DecisionTiers{
		Observe:   cfg.Tiers.Observe,
		Throttle:  cfg.Tiers.Throttle,
		Challenge: cfg.Tiers.Challenge,
		Tarpit:    cfg.Tiers.Tarpit,
		Block:     cfg.Tiers.Block,
	}
	return decision
}

func Decide(score int, confidence float64, cfg DecisionConfig) Decision {
	score = clamp(score, 0, 100)
	confidence = clampFloat(confidence, 0, 1)

	decision := mapScoreToDecision(score, cfg.Tiers)
	if confidence < cfg.BlockMinConfidence && severity(decision) > severity(DecisionChallenge) {
		return DecisionChallenge
	}
	return decision
}

func ApplyDecision(assessment RiskAssessment, cfg DecisionConfig) RiskAssessment {
	assessment.Decision = Decide(assessment.RiskScore, assessment.Confidence, cfg)
	if assessment.Profile == "" {
		assessment.Profile = cfg.Profile
	}

	if assessment.DeterministicTrigger != nil {
		assessment.DecisionBasis = DecisionBasisDeterministic
		if assessment.Confidence >= cfg.BlockMinConfidence {
			assessment.Decision = DecisionBlock
		}
		return assessment
	}

	if assessment.Decision == DecisionBlock && assessment.CorroboratingFamilies < cfg.MinCorroboratingFamilies {
		assessment.Decision = DecisionChallenge
	}
	if assessment.Decision != DecisionAllow && assessment.DecisionBasis == "" {
		assessment.DecisionBasis = DecisionBasisHeuristic
	}
	return assessment
}

func mapScoreToDecision(score int, tiers DecisionTiers) Decision {
	switch {
	case score >= tiers.Block:
		return DecisionBlock
	case score >= tiers.Tarpit:
		return DecisionTarpit
	case score >= tiers.Challenge:
		return DecisionChallenge
	case score >= tiers.Throttle:
		return DecisionThrottle
	case score >= tiers.Observe:
		return DecisionObserve
	default:
		return DecisionAllow
	}
}

func severity(decision Decision) int {
	switch decision {
	case DecisionObserve:
		return 1
	case DecisionThrottle:
		return 2
	case DecisionChallenge:
		return 3
	case DecisionTarpit:
		return 4
	case DecisionBlock:
		return 5
	default:
		return 0
	}
}
