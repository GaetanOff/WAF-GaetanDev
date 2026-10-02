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

// Journaux et métriques comptent la même action pour une même requête.
func TestEffectiveAction(t *testing.T) {
	cases := []struct {
		name     string
		response string
		request  string
		want     string
	}{
		{name: "no header is an upstream status", want: ActionPass},
		{name: "response decision", response: ActionBlock, want: ActionBlock},
		{name: "request decision", request: ActionChallenge, want: ActionChallenge},
		{name: "response wins over request", response: ActionRateLimit, request: ActionPass, want: ActionRateLimit},
		{name: "tarpit served", response: ActionTarpit, want: ActionTarpit},
		{name: "tarpit only classified", request: ActionTarpit, want: ActionPass},
		{name: "unknown value", response: "ALLOW", want: ActionPass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response, request := http.Header{}, http.Header{}
			if tc.response != "" {
				response.Set(Action, tc.response)
			}
			if tc.request != "" {
				request.Set(Action, tc.request)
			}
			if got := EffectiveAction(response, request); got != tc.want {
				t.Fatalf("EffectiveAction() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPassKinds(t *testing.T) {
	cases := []struct {
		name                  string
		action, reason        string
		pass, asset, fullPass bool
	}{
		{name: "whitelist", action: ActionPass, reason: "whitelist", pass: true, fullPass: true},
		{name: "asset", action: ActionPass, reason: ReasonStaticAsset, pass: true, asset: true},
		{name: "challenge", action: ActionChallenge, reason: ReasonStaticAsset},
		{name: "none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := http.Header{}
			if tc.action != "" {
				header.Set(Action, tc.action)
			}
			if tc.reason != "" {
				header.Set(Reason, tc.reason)
			}
			if got := IsPass(header); got != tc.pass {
				t.Errorf("IsPass = %v, want %v", got, tc.pass)
			}
			if got := IsAssetPass(header); got != tc.asset {
				t.Errorf("IsAssetPass = %v, want %v", got, tc.asset)
			}
			if got := IsFullPass(header); got != tc.fullPass {
				t.Errorf("IsFullPass = %v, want %v", got, tc.fullPass)
			}
		})
	}
}
