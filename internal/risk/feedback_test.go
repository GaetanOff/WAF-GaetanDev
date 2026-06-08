package risk

import "testing"

func TestFeedbackManagerDecreasesContributingFamilyWeight(t *testing.T) {
	feedback := NewFeedbackManager()

	feedback.RecordChallengePassAfterFlag("visitor-1", []SignalFamily{FamilyBehavioral})

	if got := feedback.WeightFactor("visitor-1", FamilyBehavioral); got != 0.9 {
		t.Fatalf("WeightFactor = %v, want 0.9", got)
	}
	if got := feedback.WeightFactor("visitor-1", FamilyReputation); got != 1.0 {
		t.Fatalf("unflagged WeightFactor = %v, want 1.0", got)
	}
}

func TestFeedbackManagerIsBounded(t *testing.T) {
	feedback := NewFeedbackManager()
	for range 20 {
		feedback.RecordChallengePassAfterFlag("visitor-1", []SignalFamily{FamilyBehavioral})
	}

	if got := feedback.WeightFactor("visitor-1", FamilyBehavioral); got != 0.5 {
		t.Fatalf("WeightFactor = %v, want lower bound 0.5", got)
	}
}

func TestFeedbackManagerAppliesWeightAdjustment(t *testing.T) {
	feedback := NewFeedbackManager()
	feedback.RecordChallengePassAfterFlag("visitor-1", []SignalFamily{FamilyBehavioral})
	cfg := DefaultFusionConfig(ProfileBalanced)

	adjusted := feedback.Apply("visitor-1", cfg)

	if adjusted.Weights[FamilyBehavioral] != cfg.Weights[FamilyBehavioral]*0.9 {
		t.Fatalf("behavioral weight = %v, want %v", adjusted.Weights[FamilyBehavioral], cfg.Weights[FamilyBehavioral]*0.9)
	}
}
