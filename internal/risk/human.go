package risk

import (
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/storage"
	"github.com/gaetandev/waf/internal/trust"
)

type HumanCreditConfig struct {
	ChallengePassed   int
	StableFingerprint int
	StickyTrustTTL    time.Duration
}

type HumanProof struct {
	ChallengePassed   bool
	StableFingerprint bool
	StickyTrust       bool
}

type HumanTrustManager struct {
	store storage.Store
	cfg   HumanCreditConfig
	now   func() time.Time
}

func HumanCreditConfigFromConfig(cfg config.HumanCredit) (HumanCreditConfig, error) {
	stickyTrustTTL, err := time.ParseDuration(cfg.StickyTrustTTL)
	if err != nil {
		return HumanCreditConfig{}, err
	}
	return HumanCreditConfig{
		ChallengePassed:   cfg.ChallengePassed,
		StableFingerprint: cfg.StableFingerprint,
		StickyTrustTTL:    stickyTrustTTL,
	}, nil
}

func NewHumanTrustManager(store storage.Store, cfg HumanCreditConfig) *HumanTrustManager {
	return &HumanTrustManager{
		store: store,
		cfg:   cfg,
		now:   time.Now,
	}
}

func (m *HumanTrustManager) GrantChallengePass(ip string, domain string, fpHash string) storage.VisitorState {
	now := m.now()
	ipHash := trust.HashIP(ip)
	var result storage.VisitorState
	m.store.UpdateVisitor(ipHash, func(current *storage.VisitorState) (storage.VisitorState, bool) {
		if current != nil {
			result = *current
		} else {
			result = storage.VisitorState{
				IPHash:    ipHash,
				Domain:    domain,
				FirstSeen: now,
				ExpiresAt: now.Add(m.cfg.StickyTrustTTL),
			}
		}
		stickyTrustUntil := now.Add(m.cfg.StickyTrustTTL)
		result.Domain = domain
		result.LastSeen = now
		result.ChallengePassed = true
		result.FPHash = &fpHash
		result.StickyTrustUntil = &stickyTrustUntil
		if result.ExpiresAt.Before(stickyTrustUntil) {
			result.ExpiresAt = stickyTrustUntil
		}
		return result, true
	})
	return result
}

func (m *HumanTrustManager) Proof(ip string, fpHash string) HumanProof {
	visitor, ok := m.store.GetVisitor(trust.HashIP(ip))
	if !ok {
		return HumanProof{}
	}

	proof := HumanProof{
		ChallengePassed: visitor.ChallengePassed,
		StickyTrust:     visitor.StickyTrustUntil != nil && visitor.StickyTrustUntil.After(m.now()),
	}
	if visitor.FPHash != nil && fpHash != "" && *visitor.FPHash == fpHash {
		proof.StableFingerprint = true
	}
	return proof
}

func (m *HumanTrustManager) Revoke(ip string) {
	m.store.UpdateVisitor(trust.HashIP(ip), func(current *storage.VisitorState) (storage.VisitorState, bool) {
		if current == nil {
			return storage.VisitorState{}, false
		}
		revoked := *current
		revoked.StickyTrustUntil = nil
		revoked.ChallengePassed = false
		return revoked, true
	})
}

func HumanCreditContribution(proof HumanProof, cfg HumanCreditConfig) Contribution {
	contribution := 0
	if proof.ChallengePassed || proof.StickyTrust {
		contribution += cfg.ChallengePassed
	}
	if proof.StableFingerprint {
		contribution += cfg.StableFingerprint
	}

	if contribution == 0 {
		return NeutralContribution(FamilyHumanCredit)
	}
	return Contribution{
		Family:       FamilyHumanCredit,
		Signal:       "human_proof",
		Value:        proof.StickyTrust,
		Contribution: ClampContribution(contribution),
		Weight:       1,
	}
}

func ApplyHumanCredit(assessment RiskAssessment, proof HumanProof) RiskAssessment {
	if assessment.DeterministicTrigger != nil {
		assessment.StickyTrust = false
		return assessment
	}

	assessment.StickyTrust = proof.StickyTrust
	if proof.ChallengePassed && proof.StableFingerprint {
		assessment.Decision = DecisionAllow
		assessment.DecisionBasis = DecisionBasisHumanCredit
		return assessment
	}
	if proof.ChallengePassed || proof.StickyTrust {
		if severity(assessment.Decision) > severity(DecisionChallenge) {
			assessment.Decision = DecisionChallenge
		}
		if assessment.DecisionBasis == "" {
			assessment.DecisionBasis = DecisionBasisHumanCredit
		}
	}
	return assessment
}
