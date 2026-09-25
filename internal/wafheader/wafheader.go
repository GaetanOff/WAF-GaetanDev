// Package wafheader nomme les en-têtes internes X-WAF-* par lesquels les
// middlewares du WAF se coordonnent, et les valeurs de X-WAF-Action. Chaque
// package redéclarait ces chaînes : une faute de frappe dans l'une d'elles
// cassait en silence la chaîne de sécurité (un PASS non reconnu, une décision
// jamais lue). L'ingress supprime tout en-tête client portant Prefix (FR-30).
package wafheader

// Prefix est le préfixe réservé aux en-têtes internes.
const Prefix = "X-WAF-"

// Décision et coordination du pipeline.
const (
	Action                 = "X-WAF-Action"
	Reason                 = "X-WAF-Reason"
	Score                  = "X-WAF-Score"
	ScoreDelta             = "X-WAF-Score-Delta"
	State                  = "X-WAF-State"
	GlobalPressure         = "X-WAF-Global-Pressure"
	UnderAttack            = "X-WAF-Under-Attack"
	UnderAttackEnforce     = "X-WAF-Under-Attack-Enforce"
	DeterministicTrigger   = "X-WAF-Deterministic-Trigger"
	FingerprintHash        = "X-WAF-Fingerprint-Hash"
	OriginToken            = "X-WAF-Origin-Token"
	UAWhitelisted          = "X-WAF-UA-Whitelisted"
	ChallengePassAfterFlag = "X-WAF-Challenge-Pass-After-Flag"
)

// RiskAssessment condensée du moteur de risque (FR-33).
const (
	RiskScore         = "X-WAF-Risk-Score"
	RiskDecision      = "X-WAF-Risk-Decision"
	RiskConfidence    = "X-WAF-Risk-Confidence"
	RiskDecisionBasis = "X-WAF-Risk-Decision-Basis"
	RiskCorroborated  = "X-WAF-Risk-Corroborated"
	RiskVerifiedBot   = "X-WAF-Risk-Verified-Bot"
	RiskShadowMode    = "X-WAF-Risk-Shadow-Mode"
)

// Contributions des familles de signaux au moteur de risque : RiskPrefix suivi
// du nom de la famille.
const (
	RiskPrefix      = "X-WAF-Risk-"
	RiskRate        = "X-WAF-Risk-rate"
	RiskTLS         = "X-WAF-Risk-tls"
	RiskIntegrity   = "X-WAF-Risk-integrity"
	RiskGeo         = "X-WAF-Risk-geo"
	RiskFingerprint = "X-WAF-Risk-fingerprint"
	RiskBehavioral  = "X-WAF-Risk-behavioral"
)

// Valeurs de X-WAF-Action.
const (
	ActionPass         = "PASS"
	ActionChallenge    = "CHALLENGE"
	ActionBlock        = "BLOCK"
	ActionRateLimit    = "RATE_LIMIT"
	ActionCircuitBreak = "CIRCUIT_BREAK"
	ActionHoneypot     = "HONEYPOT"
	ActionTarpit       = "TARPIT"
)
