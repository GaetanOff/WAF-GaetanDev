package risk

const (
	DecisionAllow     Decision = "ALLOW"
	DecisionObserve   Decision = "OBSERVE"
	DecisionThrottle  Decision = "THROTTLE"
	DecisionChallenge Decision = "CHALLENGE"
	DecisionTarpit    Decision = "TARPIT"
	DecisionBlock     Decision = "BLOCK"

	DecisionBasisHeuristic     DecisionBasis = "heuristic"
	DecisionBasisDeterministic DecisionBasis = "deterministic"
	DecisionBasisVerifiedBot   DecisionBasis = "verified_bot"
	DecisionBasisHumanCredit   DecisionBasis = "human_credit"
	DecisionBasisDefaultAllow  DecisionBasis = "default_allow"

	TriggerBlacklist           DeterministicTrigger = "blacklist"
	TriggerHoneypot            DeterministicTrigger = "honeypot"
	TriggerJA3Blacklist        DeterministicTrigger = "ja3_blacklist"
	TriggerThreatIntelCritical DeterministicTrigger = "threat_intel_critical"
	TriggerCircuitBreaker      DeterministicTrigger = "circuit_breaker"

	ProfileLenient  Profile = "lenient"
	ProfileBalanced Profile = "balanced"
	ProfileStrict   Profile = "strict"
)

type Decision string

type DecisionBasis string

type DeterministicTrigger string

type Profile string

type RiskAssessment struct {
	RiskScore             int                   `json:"risk_score"`
	Confidence            float64               `json:"confidence"`
	Decision              Decision              `json:"decision"`
	DecisionBasis         DecisionBasis         `json:"decision_basis,omitempty"`
	CorroboratingFamilies int                   `json:"corroborating_families"`
	DeterministicTrigger  *DeterministicTrigger `json:"deterministic_trigger,omitempty"`
	VerifiedGoodBot       *string               `json:"verified_good_bot,omitempty"`
	StickyTrust           bool                  `json:"sticky_trust,omitempty"`
	ShadowMode            bool                  `json:"shadow_mode"`
	Profile               Profile               `json:"profile,omitempty"`
	Factors               []Contribution        `json:"factors"`
}

func NewAssessment(score int, confidence float64, decision Decision, factors []Contribution) RiskAssessment {
	return RiskAssessment{
		RiskScore:             clamp(score, 0, 100),
		Confidence:            clampFloat(confidence, 0, 1),
		Decision:              decision,
		CorroboratingFamilies: countCorroborating(factors),
		ShadowMode:            false,
		Factors:               factors,
	}
}

func countCorroborating(factors []Contribution) int {
	count := 0
	for _, factor := range factors {
		if factor.AboveThreshold {
			count++
		}
	}
	return count
}

func clampFloat(value float64, minValue float64, maxValue float64) float64 {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
