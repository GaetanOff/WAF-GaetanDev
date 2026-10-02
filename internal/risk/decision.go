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

// DefaultDecisionConfig rend la décision du profil, sans surcharge.
func DefaultDecisionConfig(profile Profile) DecisionConfig {
	return DecisionConfigFromConfig(config.RiskEngine{Profile: string(profile)})
}

// DecisionConfigFromConfig rend la décision configurée : paliers et seuils
// absents prennent la valeur du profil (config.RiskEngine.Resolved). Ils
// écrasaient le profil, que Default() pré-remplissait avec balanced.
func DecisionConfigFromConfig(cfg config.RiskEngine) DecisionConfig {
	resolved := cfg.Resolved()
	return DecisionConfig{
		Profile:                  knownProfile(resolved.Profile),
		BlockMinConfidence:       resolved.BlockMinConfidence,
		MinCorroboratingFamilies: resolved.MinCorroboratingFamilies,
		Tiers: DecisionTiers{
			Observe:   resolved.Tiers.Observe,
			Throttle:  resolved.Tiers.Throttle,
			Challenge: resolved.Tiers.Challenge,
			Tarpit:    resolved.Tiers.Tarpit,
			Block:     resolved.Tiers.Block,
		},
	}
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
