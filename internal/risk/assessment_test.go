package risk

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRiskAssessmentSerializesAccordingToSchema(t *testing.T) {
	trigger := TriggerThreatIntelCritical
	bot := "googlebot"
	assessment := RiskAssessment{
		RiskScore:             85,
		Confidence:            0.91,
		Decision:              DecisionBlock,
		DecisionBasis:         DecisionBasisDeterministic,
		CorroboratingFamilies: 1,
		DeterministicTrigger:  &trigger,
		VerifiedGoodBot:       &bot,
		StickyTrust:           true,
		ShadowMode:            true,
		Profile:               ProfileBalanced,
		Factors: []Contribution{
			{
				Family:         FamilyReputation,
				Signal:         "abuseipdb_score",
				Value:          92,
				Contribution:   92,
				Weight:         1.5,
				AboveThreshold: true,
			},
			{
				Family:       FamilyHumanCredit,
				Signal:       "challenge_cookie",
				Value:        true,
				Contribution: -20,
				Weight:       1,
			},
		},
	}

	raw, err := json.Marshal(assessment)
	if err != nil {
		t.Fatalf("json.Marshal(RiskAssessment) error = %v", err)
	}

	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("json.Unmarshal(serialized RiskAssessment) error = %v", err)
	}

	schema := loadRiskAssessmentSchema(t)
	assertObjectMatchesSchema(t, document, schema)
}

func TestNewAssessmentClampsScoreConfidenceAndCountsCorroboratingFamilies(t *testing.T) {
	assessment := NewAssessment(120, -0.25, DecisionChallenge, []Contribution{
		{Family: FamilyReputation, Contribution: 75, Weight: 1, AboveThreshold: true},
		{Family: FamilyTLS, Contribution: 15, Weight: 1},
		{Family: FamilyRate, Contribution: 55, Weight: 1, AboveThreshold: true},
	})

	if assessment.RiskScore != 100 {
		t.Fatalf("RiskScore = %d, want 100", assessment.RiskScore)
	}
	if assessment.Confidence != 0 {
		t.Fatalf("Confidence = %v, want 0", assessment.Confidence)
	}
	if assessment.CorroboratingFamilies != 2 {
		t.Fatalf("CorroboratingFamilies = %d, want 2", assessment.CorroboratingFamilies)
	}
}

func TestNeutralContributionDefaultsAbsentFamilyToNoRisk(t *testing.T) {
	contribution := NeutralContribution(FamilyGeo)

	if contribution.Family != FamilyGeo {
		t.Fatalf("Family = %s, want %s", contribution.Family, FamilyGeo)
	}
	if contribution.Contribution != 0 {
		t.Fatalf("Contribution = %d, want 0", contribution.Contribution)
	}
	if contribution.Weight != 0 {
		t.Fatalf("Weight = %v, want 0", contribution.Weight)
	}
	if contribution.AboveThreshold {
		t.Fatal("AboveThreshold = true, want false")
	}
}

func TestCollectContributionsCompletesAbsentFamiliesWithNeutralDefaults(t *testing.T) {
	contributions := CollectContributions([]SignalProvider{
		staticSignalProvider{
			family: FamilyReputation,
			contribution: Contribution{
				Signal:       "abuseipdb_score",
				Contribution: 125,
				Weight:       1,
			},
		},
	})

	if len(contributions) != len(Families()) {
		t.Fatalf("len(contributions) = %d, want %d", len(contributions), len(Families()))
	}
	if contributions[0].Family != FamilyReputation {
		t.Fatalf("first contribution family = %s, want %s", contributions[0].Family, FamilyReputation)
	}
	if contributions[0].Contribution != 100 {
		t.Fatalf("reputation contribution = %d, want clamped 100", contributions[0].Contribution)
	}
	for _, contribution := range contributions[1:] {
		if contribution.Contribution != 0 || contribution.Weight != 0 {
			t.Fatalf("absent family contribution = %+v, want neutral", contribution)
		}
	}
}

func TestClampContributionUsesSchemaBounds(t *testing.T) {
	tests := []struct {
		name  string
		value int
		want  int
	}{
		{name: "below minimum", value: -150, want: -100},
		{name: "inside bounds", value: 42, want: 42},
		{name: "above maximum", value: 125, want: 100},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClampContribution(tt.value); got != tt.want {
				t.Fatalf("ClampContribution(%d) = %d, want %d", tt.value, got, tt.want)
			}
		})
	}
}

func loadRiskAssessmentSchema(t *testing.T) map[string]any {
	t.Helper()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(currentFile), "..", "..", "specs", "schemas", "risk-assessment.schema.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%s) error = %v", path, err)
	}

	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("json.Unmarshal(risk-assessment schema) error = %v", err)
	}
	return schema
}

func assertObjectMatchesSchema(t *testing.T, document map[string]any, schema map[string]any) {
	t.Helper()

	required := stringSlice(t, schema["required"])
	for _, name := range required {
		if _, ok := document[name]; !ok {
			t.Fatalf("serialized RiskAssessment missing required field %q in %v", name, document)
		}
	}

	properties := objectMap(t, schema["properties"])
	for name := range document {
		if _, ok := properties[name]; !ok {
			t.Fatalf("serialized RiskAssessment has additional property %q", name)
		}
	}

	assertNumberInRange(t, document["risk_score"], properties["risk_score"])
	assertNumberInRange(t, document["confidence"], properties["confidence"])
	assertEnumContains(t, document["decision"], properties["decision"])
	assertEnumContains(t, document["decision_basis"], properties["decision_basis"])
	assertNumberInRange(t, document["corroborating_families"], properties["corroborating_families"])
	assertEnumContains(t, document["deterministic_trigger"], properties["deterministic_trigger"])
	assertEnumContains(t, document["profile"], properties["profile"])

	factors, ok := document["factors"].([]any)
	if !ok {
		t.Fatalf("factors has type %T, want array", document["factors"])
	}
	factorSchema := objectMap(t, objectMap(t, properties["factors"])["items"])
	factorProperties := objectMap(t, factorSchema["properties"])
	for _, rawFactor := range factors {
		factor, ok := rawFactor.(map[string]any)
		if !ok {
			t.Fatalf("factor has type %T, want object", rawFactor)
		}
		for _, name := range stringSlice(t, factorSchema["required"]) {
			if _, ok := factor[name]; !ok {
				t.Fatalf("serialized factor missing required field %q in %v", name, factor)
			}
		}
		for name := range factor {
			if _, ok := factorProperties[name]; !ok {
				t.Fatalf("serialized factor has additional property %q", name)
			}
		}
		assertEnumContains(t, factor["family"], factorProperties["family"])
		assertNumberInRange(t, factor["contribution"], factorProperties["contribution"])
		assertNumberInRange(t, factor["weight"], factorProperties["weight"])
	}
}

func assertNumberInRange(t *testing.T, value any, schema any) {
	t.Helper()

	number, ok := value.(float64)
	if !ok {
		t.Fatalf("value %v has type %T, want number", value, value)
	}
	property := objectMap(t, schema)
	if minimum, ok := property["minimum"].(float64); ok && number < minimum {
		t.Fatalf("value %v below minimum %v", number, minimum)
	}
	if maximum, ok := property["maximum"].(float64); ok && number > maximum {
		t.Fatalf("value %v above maximum %v", number, maximum)
	}
}

func assertEnumContains(t *testing.T, value any, schema any) {
	t.Helper()

	for _, allowed := range objectMap(t, schema)["enum"].([]any) {
		if value == allowed {
			return
		}
	}
	t.Fatalf("value %v not allowed by enum %v", value, objectMap(t, schema)["enum"])
}

func objectMap(t *testing.T, value any) map[string]any {
	t.Helper()

	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value has type %T, want object", value)
	}
	return object
}

func stringSlice(t *testing.T, value any) []string {
	t.Helper()

	values, ok := value.([]any)
	if !ok {
		t.Fatalf("value has type %T, want array", value)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			t.Fatalf("value has type %T, want string", value)
		}
		result = append(result, text)
	}
	return result
}

type staticSignalProvider struct {
	family       SignalFamily
	contribution Contribution
}

func (p staticSignalProvider) SignalFamily() SignalFamily {
	return p.family
}

func (p staticSignalProvider) Contribution() Contribution {
	return p.contribution
}
