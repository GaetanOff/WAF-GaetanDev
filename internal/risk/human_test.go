package risk

import (
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/trust"
)

const testFPHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestHumanTrustManagerGrantsStickyTrustWithTTL(t *testing.T) {
	store := memory.New(10)
	defer store.Close()
	manager := newTestHumanTrustManager(store)
	// Date loin dans le futur : le memory store expire les visiteurs à la lecture
	// sur l'horloge réelle ; un fixture daté « aujourd'hui » deviendrait expiré
	// dès que le temps réel dépasse le TTL. Une date future garde le test stable.
	now := time.Date(2126, 6, 8, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }

	visitor := manager.GrantChallengePass("1.2.3.4", "example.test", testFPHash)

	if !visitor.ChallengePassed {
		t.Fatal("ChallengePassed = false, want true")
	}
	if visitor.FPHash == nil || *visitor.FPHash != testFPHash {
		t.Fatalf("FPHash = %v, want %s", visitor.FPHash, testFPHash)
	}
	if visitor.StickyTrustUntil == nil || !visitor.StickyTrustUntil.Equal(now.Add(30*time.Minute)) {
		t.Fatalf("StickyTrustUntil = %v, want %v", visitor.StickyTrustUntil, now.Add(30*time.Minute))
	}
}

func TestHumanTrustManagerProofDetectsStableFingerprint(t *testing.T) {
	store := memory.New(10)
	defer store.Close()
	manager := newTestHumanTrustManager(store)
	// Date loin dans le futur : le memory store expire les visiteurs à la lecture
	// sur l'horloge réelle ; un fixture daté « aujourd'hui » deviendrait expiré
	// dès que le temps réel dépasse le TTL. Une date future garde le test stable.
	now := time.Date(2126, 6, 8, 12, 0, 0, 0, time.UTC)
	manager.now = func() time.Time { return now }
	manager.GrantChallengePass("1.2.3.4", "example.test", testFPHash)

	proof := manager.Proof("1.2.3.4", testFPHash)

	if !proof.ChallengePassed {
		t.Fatal("ChallengePassed = false, want true")
	}
	if !proof.StickyTrust {
		t.Fatal("StickyTrust = false, want true")
	}
	if !proof.StableFingerprint {
		t.Fatal("StableFingerprint = false, want true")
	}
}

func TestHumanTrustManagerRevokesStickyTrust(t *testing.T) {
	store := memory.New(10)
	defer store.Close()
	manager := newTestHumanTrustManager(store)
	manager.GrantChallengePass("1.2.3.4", "example.test", testFPHash)

	manager.Revoke("1.2.3.4")

	visitor, ok := store.GetVisitor(trust.HashIP("1.2.3.4"))
	if !ok {
		t.Fatal("visitor missing")
	}
	if visitor.ChallengePassed {
		t.Fatal("ChallengePassed = true, want false")
	}
	if visitor.StickyTrustUntil != nil {
		t.Fatalf("StickyTrustUntil = %v, want nil", visitor.StickyTrustUntil)
	}
}

func TestHumanCreditContributionIsNegativeForStrongProof(t *testing.T) {
	cfg := HumanCreditConfig{
		ChallengePassed:   -40,
		StableFingerprint: -15,
		StickyTrustTTL:    30 * time.Minute,
	}

	contribution := HumanCreditContribution(HumanProof{
		ChallengePassed:   true,
		StableFingerprint: true,
		StickyTrust:       true,
	}, cfg)

	if contribution.Family != FamilyHumanCredit {
		t.Fatalf("Family = %s, want human_credit", contribution.Family)
	}
	if contribution.Contribution != -55 {
		t.Fatalf("Contribution = %d, want -55", contribution.Contribution)
	}
}

func TestApplyHumanCreditAllowsStrongHumanProof(t *testing.T) {
	assessment := RiskAssessment{
		RiskScore:             80,
		Confidence:            0.9,
		Decision:              DecisionChallenge,
		DecisionBasis:         DecisionBasisHeuristic,
		CorroboratingFamilies: 2,
	}

	updated := ApplyHumanCredit(assessment, HumanProof{
		ChallengePassed:   true,
		StableFingerprint: true,
		StickyTrust:       true,
	})

	if updated.Decision != DecisionAllow {
		t.Fatalf("Decision = %s, want ALLOW", updated.Decision)
	}
	if updated.DecisionBasis != DecisionBasisHumanCredit {
		t.Fatalf("DecisionBasis = %s, want human_credit", updated.DecisionBasis)
	}
	if !updated.StickyTrust {
		t.Fatal("StickyTrust = false, want true")
	}
}

func TestApplyHumanCreditCapsHeuristicBlockAtChallenge(t *testing.T) {
	assessment := RiskAssessment{
		RiskScore:             95,
		Confidence:            0.9,
		Decision:              DecisionBlock,
		DecisionBasis:         DecisionBasisHeuristic,
		CorroboratingFamilies: 2,
	}

	updated := ApplyHumanCredit(assessment, HumanProof{
		ChallengePassed: true,
		StickyTrust:     true,
	})

	if updated.Decision != DecisionChallenge {
		t.Fatalf("Decision = %s, want CHALLENGE", updated.Decision)
	}
}

func TestApplyHumanCreditDoesNotOverrideDeterministicBlock(t *testing.T) {
	trigger := TriggerHoneypot
	assessment := RiskAssessment{
		RiskScore:            95,
		Confidence:           0.9,
		Decision:             DecisionBlock,
		DecisionBasis:        DecisionBasisDeterministic,
		DeterministicTrigger: &trigger,
		StickyTrust:          true,
	}

	updated := ApplyHumanCredit(assessment, HumanProof{
		ChallengePassed:   true,
		StableFingerprint: true,
		StickyTrust:       true,
	})

	if updated.Decision != DecisionBlock {
		t.Fatalf("Decision = %s, want BLOCK", updated.Decision)
	}
	if updated.StickyTrust {
		t.Fatal("StickyTrust = true, want false")
	}
}

func newTestHumanTrustManager(store *memory.Store) *HumanTrustManager {
	return NewHumanTrustManager(store, HumanCreditConfig{
		ChallengePassed:   -40,
		StableFingerprint: -15,
		StickyTrustTTL:    30 * time.Minute,
	})
}
