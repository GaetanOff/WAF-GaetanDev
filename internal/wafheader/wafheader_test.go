package wafheader

import (
	"net/http"
	"testing"
)

var headers = []string{
	Prefix, Action, Reason, Score, ScoreDelta, State, GlobalPressure, UnderAttack,
	UnderAttackEnforce, DeterministicTrigger, FingerprintHash, OriginToken,
	UAWhitelisted, ChallengePassAfterFlag, RiskScore, RiskDecision,
	RiskConfidence, RiskDecisionBasis, RiskCorroborated, RiskVerifiedBot,
	RiskShadowMode, RiskPrefix, RiskRate, RiskTLS, RiskIntegrity, RiskGeo,
	RiskFingerprint, RiskBehavioral,
}

// Un nom non canonique fait allouer Header.Get et Header.Set à chaque appel.
func TestHeaderNamesAreCanonical(t *testing.T) {
	for _, name := range headers {
		if canonical := http.CanonicalHeaderKey(name); canonical != name {
			t.Errorf("%q is not canonical, want %q", name, canonical)
		}
	}
}

func TestGetDoesNotAllocate(t *testing.T) {
	header := http.Header{}
	header.Set(Action, ActionPass)
	if allocs := testing.AllocsPerRun(100, func() { _ = header.Get(Action) }); allocs != 0 {
		t.Fatalf("Header.Get(Action) allocates %v times, want 0", allocs)
	}
}
