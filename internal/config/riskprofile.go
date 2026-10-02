package config

import "maps"

// Modes de fusion du moteur de risque (risk_engine.fusion, FR-33).
const (
	// FusionDiluted divise la somme pondérée par la somme de tous les poids.
	FusionDiluted = "diluted"
	// FusionAvailable la divise par la somme des poids des familles portant
	// une évidence.
	FusionAvailable = "available"
)

// riskProfile est le préréglage d'un profil du moteur de risque (FR-33).
type riskProfile struct {
	blockMinConfidence           float64
	minCorroboratingFamilies     int
	tiers                        RiskTiers
	weights                      map[string]float64
	familyCorroborationThreshold int
}

var riskProfiles = map[string]riskProfile{
	"lenient": {
		blockMinConfidence:       0.75,
		minCorroboratingFamilies: 2,
		tiers:                    RiskTiers{Observe: 35, Throttle: 55, Challenge: 75, Tarpit: 88, Block: 96},
		weights: map[string]float64{
			"reputation": 0.6, "behavioral": 0.7, "tls": 0.5, "fingerprint": 0.7,
			"integrity": 0.9, "rate": 0.3, "geo": 0.2, "human_credit": 3.0,
		},
		familyCorroborationThreshold: 60,
	},
	"balanced": {
		blockMinConfidence:       0.6,
		minCorroboratingFamilies: 2,
		tiers:                    RiskTiers{Observe: 25, Throttle: 45, Challenge: 65, Tarpit: 80, Block: 90},
		weights: map[string]float64{
			"reputation": 1.0, "behavioral": 1.0, "tls": 0.8, "fingerprint": 1.0,
			"integrity": 1.2, "rate": 0.6, "geo": 0.5, "human_credit": 1.0,
		},
		familyCorroborationThreshold: 50,
	},
	"strict": {
		blockMinConfidence:       0.5,
		minCorroboratingFamilies: 2,
		tiers:                    RiskTiers{Observe: 15, Throttle: 35, Challenge: 55, Tarpit: 72, Block: 85},
		weights: map[string]float64{
			"reputation": 1.8, "behavioral": 1.5, "tls": 1.2, "fingerprint": 1.5,
			"integrity": 1.6, "rate": 1.0, "geo": 0.8, "human_credit": 0.5,
		},
		familyCorroborationThreshold: 45,
	},
}

// Resolved rend la configuration du moteur dont chaque palier, poids et seuil
// absent (ou à 0) prend la valeur du profil, poids par poids pour weights
// (FR-33) ; une valeur explicite prime. Un profil inconnu vaut balanced, une
// fusion vide diluted. Default() pré-remplissait ces clés avec les valeurs
// balanced : profile strict ou lenient n'avait aucun effet.
func (r RiskEngine) Resolved() RiskEngine {
	preset, ok := riskProfiles[r.Profile]
	if !ok {
		preset = riskProfiles["balanced"]
	}
	if r.Fusion == "" {
		r.Fusion = FusionDiluted
	}
	if r.BlockMinConfidence == 0 {
		r.BlockMinConfidence = preset.blockMinConfidence
	}
	if r.MinCorroboratingFamilies == 0 {
		r.MinCorroboratingFamilies = preset.minCorroboratingFamilies
	}
	if r.FamilyCorroborationThreshold == 0 {
		r.FamilyCorroborationThreshold = preset.familyCorroborationThreshold
	}
	r.Tiers = r.Tiers.orDefaults(preset.tiers)
	weights := maps.Clone(preset.weights)
	maps.Copy(weights, r.Weights)
	r.Weights = weights
	return r
}

func (t RiskTiers) orDefaults(preset RiskTiers) RiskTiers {
	pick := func(value, fallback int) int {
		if value == 0 {
			return fallback
		}
		return value
	}
	return RiskTiers{
		Observe:   pick(t.Observe, preset.Observe),
		Throttle:  pick(t.Throttle, preset.Throttle),
		Challenge: pick(t.Challenge, preset.Challenge),
		Tarpit:    pick(t.Tarpit, preset.Tarpit),
		Block:     pick(t.Block, preset.Block),
	}
}
