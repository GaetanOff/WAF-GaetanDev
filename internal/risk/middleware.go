package risk

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/storage"
	"github.com/gaetandev/waf/internal/trust"
)

const (
	headerAction               = "X-WAF-Action"
	headerReason               = "X-WAF-Reason"
	headerScore                = "X-WAF-Score"
	headerScoreDelta           = "X-WAF-Score-Delta"
	headerRiskScore            = "X-WAF-Risk-Score"
	headerRiskDecision         = "X-WAF-Risk-Decision"
	headerRiskConfidence       = "X-WAF-Risk-Confidence"
	headerDeterministicTrigger = "X-WAF-Deterministic-Trigger"
	headerFingerprintHash      = "X-WAF-Fingerprint-Hash"
)

type Middleware struct {
	scores   *trust.ScoreManager
	fusion   FusionConfig
	decision DecisionConfig
	humans   *HumanTrustManager
	bots     *BotVerifier
}

func NewMiddleware(store storage.Store, scores *trust.ScoreManager, cfg config.Config) (*Middleware, error) {
	humanConfig, err := HumanCreditConfigFromConfig(cfg.RiskEngine.HumanCredit)
	if err != nil {
		return nil, err
	}
	botConfig, err := BotVerifierConfigFromConfig(cfg.RiskEngine.VerifiedBots)
	if err != nil {
		return nil, err
	}
	return &Middleware{
		scores:   scores,
		fusion:   FusionConfigFromConfig(cfg.RiskEngine),
		decision: DecisionConfigFromConfig(cfg.RiskEngine),
		humans:   NewHumanTrustManager(store, humanConfig),
		bots:     NewBotVerifier(botConfig, nil),
	}, nil
}

func NewMiddlewareWithVerifier(scores *trust.ScoreManager, fusion FusionConfig, decision DecisionConfig, humans *HumanTrustManager, bots *BotVerifier) *Middleware {
	return &Middleware{
		scores:   scores,
		fusion:   fusion,
		decision: decision,
		humans:   humans,
		bots:     bots,
	}
}

func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerAction) == "PASS" {
			next.ServeHTTP(w, r)
			return
		}

		assessment := m.assess(r)
		m.writeHeaders(r, assessment)

		switch assessment.Decision {
		case DecisionBlock:
			w.Header().Set(headerAction, string(DecisionBlock))
			w.Header().Set(headerReason, reasonForAssessment(assessment))
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		case DecisionChallenge:
			r.Header.Set(headerAction, string(DecisionChallenge))
			r.Header.Set(headerReason, reasonForAssessment(assessment))
		case DecisionThrottle, DecisionTarpit, DecisionObserve:
			r.Header.Set(headerAction, string(assessment.Decision))
			r.Header.Set(headerReason, reasonForAssessment(assessment))
		}

		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) assess(r *http.Request) RiskAssessment {
	ip := cloudflare.RealIP(r)
	visitor := m.scores.Get(ip, r.Host)
	contributions := CollectContributions(signalProvidersFromRequest(r, visitor.Score))
	assessment := Fuse(contributions, m.fusion)
	assessment = applyDeterministicTrigger(assessment, r.Header.Get(headerDeterministicTrigger))
	assessment = ApplyDecision(assessment, m.decision)

	if m.bots != nil {
		verification := m.bots.Check(ip, r.UserAgent())
		if verification.State == BotVerificationSpoofed {
			assessment.Factors = appendOrReplaceFactor(assessment.Factors, BotVerificationContribution(verification))
			assessment = NewAssessment(assessment.RiskScore, assessment.Confidence, assessment.Decision, assessment.Factors)
			assessment = ApplyDecision(assessment, m.decision)
		}
		assessment = ApplyBotVerification(assessment, verification)
	}
	if m.humans != nil {
		proof := m.humans.Proof(ip, r.Header.Get(headerFingerprintHash))
		if proof.ChallengePassed || proof.StickyTrust || proof.StableFingerprint {
			assessment.Factors = appendOrReplaceFactor(assessment.Factors, HumanCreditContribution(proof, m.humans.cfg))
			assessment = Fuse(assessment.Factors, m.fusion)
			assessment = ApplyDecision(assessment, m.decision)
			assessment = ApplyHumanCredit(assessment, proof)
		}
		if assessment.DeterministicTrigger != nil {
			m.humans.Revoke(ip)
		}
	}

	return assessment
}

func (m *Middleware) writeHeaders(r *http.Request, assessment RiskAssessment) {
	r.Header.Set(headerRiskScore, strconv.Itoa(assessment.RiskScore))
	r.Header.Set(headerRiskDecision, string(assessment.Decision))
	r.Header.Set(headerRiskConfidence, strconv.FormatFloat(assessment.Confidence, 'f', 3, 64))
	r.Header.Set(headerScoreDelta, strconv.Itoa(assessment.RiskScore-50))
	if r.Header.Get(headerScore) == "" {
		r.Header.Set(headerScore, strconv.Itoa(100-assessment.RiskScore))
	}
}

func signalProvidersFromRequest(r *http.Request, trustScore int) []SignalProvider {
	providers := []SignalProvider{
		staticProvider{
			family: FamilyReputation,
			contribution: Contribution{
				Family:       FamilyReputation,
				Signal:       "trust_score",
				Value:        trustScore,
				Contribution: 100 - trustScore,
			},
		},
	}
	for _, family := range Families() {
		if family == FamilyReputation || family == FamilyHumanCredit {
			continue
		}
		header := "X-WAF-Risk-" + strings.ReplaceAll(string(family), "_", "-")
		value, ok := parseHeaderInt(r.Header.Get(header))
		if !ok {
			continue
		}
		providers = append(providers, staticProvider{
			family: family,
			contribution: Contribution{
				Family:       family,
				Signal:       strings.ToLower(header),
				Value:        value,
				Contribution: value,
			},
		})
	}
	return providers
}

func applyDeterministicTrigger(assessment RiskAssessment, raw string) RiskAssessment {
	if raw == "" {
		return assessment
	}
	trigger := DeterministicTrigger(raw)
	switch trigger {
	case TriggerBlacklist, TriggerHoneypot, TriggerJA3Blacklist, TriggerThreatIntelCritical, TriggerCircuitBreaker:
		assessment.DeterministicTrigger = &trigger
		assessment.Confidence = 1
		assessment.RiskScore = 100
	}
	return assessment
}

func appendOrReplaceFactor(factors []Contribution, factor Contribution) []Contribution {
	if factor.Signal == "" && factor.Contribution == 0 {
		return factors
	}
	for index := range factors {
		if factors[index].Family == factor.Family {
			factors[index] = factor
			return factors
		}
	}
	return append(factors, factor)
}

func reasonForAssessment(assessment RiskAssessment) string {
	if assessment.DeterministicTrigger != nil {
		return "risk_deterministic_" + string(*assessment.DeterministicTrigger)
	}
	if assessment.DecisionBasis != "" {
		return "risk_" + string(assessment.DecisionBasis)
	}
	return "risk_" + strings.ToLower(string(assessment.Decision))
}

func parseHeaderInt(raw string) (int, bool) {
	if raw == "" {
		return 0, false
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return value, true
}

type staticProvider struct {
	family       SignalFamily
	contribution Contribution
}

func (p staticProvider) SignalFamily() SignalFamily {
	return p.family
}

func (p staticProvider) Contribution() Contribution {
	return p.contribution
}
