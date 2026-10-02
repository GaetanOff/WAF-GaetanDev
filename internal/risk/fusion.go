package risk

import "github.com/gaetandev/waf/internal/config"

// FusionMode est le mode de fusion (risk_engine.fusion, FR-33).
type FusionMode string

const (
	// FusionDiluted divise la somme pondérée par la somme de tous les poids
	// configurés : un BLOCK heuristique y est inatteignable par défaut.
	FusionDiluted FusionMode = config.FusionDiluted
	// FusionAvailable la divise par la somme des poids des seules familles
	// portant une évidence, avec une réputation neutre au score initial.
	FusionAvailable FusionMode = config.FusionAvailable
)

type FusionConfig struct {
	Profile                      Profile
	Mode                         FusionMode
	Weights                      map[SignalFamily]float64
	FamilyCorroborationThreshold int
	// InitialTrustScore est le score de confiance d'un nouveau visiteur
	// (trust.initial_score) : la réputation y est neutre en mode available.
	InitialTrustScore int
}

// DefaultFusionConfig rend la fusion du profil, sans surcharge.
func DefaultFusionConfig(profile Profile) FusionConfig {
	return FusionConfigFromConfig(config.RiskEngine{Profile: string(profile)})
}

// FusionConfigFromConfig rend la fusion configurée : poids et seuil absents
// prennent la valeur du profil (config.RiskEngine.Resolved).
func FusionConfigFromConfig(cfg config.RiskEngine) FusionConfig {
	resolved := cfg.Resolved()
	weights := make(map[SignalFamily]float64, len(resolved.Weights))
	for family, weight := range resolved.Weights {
		weights[SignalFamily(family)] = weight
	}
	return FusionConfig{
		Profile:                      knownProfile(resolved.Profile),
		Mode:                         FusionMode(resolved.Fusion),
		Weights:                      weights,
		FamilyCorroborationThreshold: resolved.FamilyCorroborationThreshold,
	}
}

// knownProfile ramène un profil inconnu à balanced, dont il reçoit les valeurs.
func knownProfile(profile string) Profile {
	switch Profile(profile) {
	case ProfileLenient, ProfileStrict:
		return Profile(profile)
	default:
		return ProfileBalanced
	}
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
	evidenceWeight := 0.0
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
			if normalized.Contribution != 0 {
				evidenceWeight += weight
			}
		}
		factors = append(factors, normalized)
	}

	score := scoreFor(weightedRisk, totalWeight, evidenceWeight, cfg.Mode)
	assessment := NewAssessment(score, availableWeight/totalWeight, DecisionAllow, factors)
	assessment.Profile = cfg.Profile
	return assessment
}

// scoreFor normalise la somme pondérée selon le mode (FR-33). En mode
// available, une famille sans évidence (contribution nulle) ne dilue pas
// celles qui en portent ; sans aucune évidence, le score est nul.
func scoreFor(weightedRisk, totalWeight, evidenceWeight float64, mode FusionMode) int {
	if mode != FusionAvailable {
		return round(weightedRisk / totalWeight)
	}
	if evidenceWeight == 0 {
		return 0
	}
	return round(weightedRisk / evidenceWeight)
}

// reputationContribution traduit le trust score en contribution de la famille
// reputation. En mode diluted, 100 - score (historique). En mode available,
// l'écart sous le score initial : un nouveau visiteur n'apporte aucune
// évidence, un visiteur à 0 en apporte 100 — sinon tout nouveau visiteur
// (contribution 50) serait classé THROTTLE.
func reputationContribution(trustScore int, cfg FusionConfig) int {
	if cfg.Mode != FusionAvailable || cfg.InitialTrustScore <= 0 {
		return 100 - trustScore
	}
	return clamp((cfg.InitialTrustScore-trustScore)*100/cfg.InitialTrustScore, 0, 100)
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
