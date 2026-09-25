package risk

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/storage"
	"github.com/gaetandev/waf/internal/trust"
	"github.com/gaetandev/waf/internal/wafheader"
)

const (
	headerAction               = wafheader.Action
	headerReason               = wafheader.Reason
	headerScore                = wafheader.Score
	headerScoreDelta           = wafheader.ScoreDelta
	headerRiskScore            = wafheader.RiskScore
	headerRiskDecision         = wafheader.RiskDecision
	headerRiskConfidence       = wafheader.RiskConfidence
	headerRiskDecisionBasis    = wafheader.RiskDecisionBasis
	headerRiskCorroborated     = wafheader.RiskCorroborated
	headerRiskVerifiedBot      = wafheader.RiskVerifiedBot
	headerRiskShadowMode       = wafheader.RiskShadowMode
	headerDeterministicTrigger = wafheader.DeterministicTrigger
	headerFingerprintHash      = wafheader.FingerprintHash
)

type Middleware struct {
	scores   *trust.ScoreManager
	fusion   FusionConfig
	decision DecisionConfig
	humans   *HumanTrustManager
	bots     *BotVerifier
	shadow   bool
	// throttle applique la décision THROTTLE (FR-34) au rate limit, monté en
	// amont : sans lui, THROTTLE n'était qu'un en-tête que personne ne lisait.
	throttle func(ip string)
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
		shadow:   cfg.RiskEngine.ShadowMode,
	}, nil
}

func NewMiddlewareWithVerifier(scores *trust.ScoreManager, fusion FusionConfig, decision DecisionConfig, humans *HumanTrustManager, bots *BotVerifier, shadow bool) *Middleware {
	return &Middleware{
		scores:   scores,
		fusion:   fusion,
		decision: decision,
		humans:   humans,
		bots:     bots,
		shadow:   shadow,
	}
}

// Close arrête les workers de vérification des crawlers (FR-36). Le
// vérificateur est construit avec le middleware, moteur de risque actif ou non.
func (m *Middleware) Close() {
	if m.bots != nil {
		m.bots.Close()
	}
}

// WithThrottle branche l'effet de la décision THROTTLE : le visiteur voit son
// débit réduit par le rate limit (FR-34, « transmis avec rate limit réduit »).
func (m *Middleware) WithThrottle(fn func(ip string)) *Middleware {
	m.throttle = fn
	return m
}

// GrantChallengePass enregistre la preuve humaine d'un challenge réussi
// (FR-37) : challenge réussi et fingerprint, que le cookie de clearance
// retransmet ensuite via X-WAF-Fingerprint-Hash.
func (m *Middleware) GrantChallengePass(ip string, domain string, fpHash string) {
	if m.humans != nil {
		m.humans.GrantChallengePass(ip, domain, fpHash)
	}
}

func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerAction) == wafheader.ActionPass {
			next.ServeHTTP(w, r)
			return
		}

		assessment := m.assess(r)
		if m.shadow {
			assessment.ShadowMode = true
		}
		m.writeHeaders(r, assessment)
		if assessment.ShadowMode {
			next.ServeHTTP(w, r)
			return
		}

		switch assessment.Decision {
		case DecisionBlock:
			w.Header().Set(headerAction, string(DecisionBlock))
			w.Header().Set(headerReason, reasonForAssessment(assessment))
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		case DecisionChallenge:
			r.Header.Set(headerAction, string(DecisionChallenge))
			r.Header.Set(headerReason, reasonForAssessment(assessment))
		case DecisionThrottle:
			r.Header.Set(headerAction, string(DecisionThrottle))
			r.Header.Set(headerReason, reasonForAssessment(assessment))
			if m.throttle != nil {
				m.throttle(cloudflare.RealIP(r))
			}
		case DecisionTarpit, DecisionObserve:
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
	if assessment.DecisionBasis != "" {
		r.Header.Set(headerRiskDecisionBasis, string(assessment.DecisionBasis))
	}
	if assessment.CorroboratingFamilies >= m.decision.MinCorroboratingFamilies {
		r.Header.Set(headerRiskCorroborated, "true")
	}
	if assessment.VerifiedGoodBot != nil {
		r.Header.Set(headerRiskVerifiedBot, *assessment.VerifiedGoodBot)
	}
	if assessment.ShadowMode {
		r.Header.Set(headerRiskShadowMode, "true")
	}
	r.Header.Set(headerScoreDelta, strconv.Itoa(assessment.RiskScore-50))
	if r.Header.Get(headerScore) == "" {
		r.Header.Set(headerScore, strconv.Itoa(100-assessment.RiskScore))
	}
}

// familyHeaders associe chaque famille publiée par un détecteur à son en-tête
// de contribution, sous forme canonique. Le nom était reconstruit (concaténation
// puis canonicalisation par Header.Get) pour chaque famille à chaque requête.
var familyHeaders = func() map[SignalFamily]string {
	headers := make(map[SignalFamily]string)
	for _, family := range Families() {
		if family == FamilyReputation || family == FamilyHumanCredit {
			continue
		}
		headers[family] = http.CanonicalHeaderKey(wafheader.RiskPrefix + strings.ReplaceAll(string(family), "_", "-"))
	}
	return headers
}()

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
		header, published := familyHeaders[family]
		if !published {
			continue
		}
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
