package risk

const (
	FamilyReputation  SignalFamily = "reputation"
	FamilyBehavioral  SignalFamily = "behavioral"
	FamilyTLS         SignalFamily = "tls"
	FamilyFingerprint SignalFamily = "fingerprint"
	FamilyIntegrity   SignalFamily = "integrity"
	FamilyRate        SignalFamily = "rate"
	FamilyGeo         SignalFamily = "geo"
	FamilyHumanCredit SignalFamily = "human_credit"
)

type SignalFamily string

type Contribution struct {
	Family         SignalFamily `json:"family"`
	Signal         string       `json:"signal,omitempty"`
	Value          any          `json:"value,omitempty"`
	Contribution   int          `json:"contribution"`
	Weight         float64      `json:"weight"`
	AboveThreshold bool         `json:"above_threshold,omitempty"`
}

type SignalProvider interface {
	SignalFamily() SignalFamily
	Contribution() Contribution
}

func CollectContributions(providers []SignalProvider) []Contribution {
	byFamily := make(map[SignalFamily]Contribution, len(providers))
	for _, provider := range providers {
		contribution := provider.Contribution()
		if contribution.Family == "" {
			contribution.Family = provider.SignalFamily()
		}
		contribution.Contribution = ClampContribution(contribution.Contribution)
		byFamily[provider.SignalFamily()] = contribution
	}

	contributions := make([]Contribution, 0, len(Families()))
	for _, family := range Families() {
		contribution, ok := byFamily[family]
		if !ok {
			contribution = NeutralContribution(family)
		}
		contributions = append(contributions, contribution)
	}
	return contributions
}

func Families() []SignalFamily {
	return []SignalFamily{
		FamilyReputation,
		FamilyBehavioral,
		FamilyTLS,
		FamilyFingerprint,
		FamilyIntegrity,
		FamilyRate,
		FamilyGeo,
		FamilyHumanCredit,
	}
}

func NeutralContribution(family SignalFamily) Contribution {
	return Contribution{
		Family:       family,
		Contribution: 0,
		Weight:       0,
	}
}

func ClampContribution(value int) int {
	return clamp(value, -100, 100)
}

func clamp(value int, minValue int, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
