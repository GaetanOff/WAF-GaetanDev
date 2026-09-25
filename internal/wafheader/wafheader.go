// Package wafheader nomme les en-têtes internes X-WAF-* par lesquels les
// middlewares du WAF se coordonnent, et les valeurs de X-WAF-Action. Chaque
// package redéclarait ces chaînes : une faute de frappe dans l'une d'elles
// cassait en silence la chaîne de sécurité (un PASS non reconnu, une décision
// jamais lue). L'ingress supprime tout en-tête client portant Prefix (FR-30).
//
// Les noms sont écrits sous leur forme canonique net/http (« X-Waf-Action ») :
// Header.Get et Header.Set canonicalisent leur clé, ce qui alloue à chaque
// appel quand elle ne l'est pas déjà (« X-WAF-Action »), soit une allocation
// et ~70 ns par lecture, des dizaines de fois par requête. Sur le fil, rien ne
// change : Set émettait déjà la forme canonique, et les noms d'en-têtes sont
// insensibles à la casse.
package wafheader

// Prefix est le préfixe réservé aux en-têtes internes.
const Prefix = "X-Waf-"

// Décision et coordination du pipeline.
const (
	Action                 = "X-Waf-Action"
	Reason                 = "X-Waf-Reason"
	Score                  = "X-Waf-Score"
	ScoreDelta             = "X-Waf-Score-Delta"
	State                  = "X-Waf-State"
	GlobalPressure         = "X-Waf-Global-Pressure"
	UnderAttack            = "X-Waf-Under-Attack"
	UnderAttackEnforce     = "X-Waf-Under-Attack-Enforce"
	DeterministicTrigger   = "X-Waf-Deterministic-Trigger"
	FingerprintHash        = "X-Waf-Fingerprint-Hash"
	OriginToken            = "X-Waf-Origin-Token"
	UAWhitelisted          = "X-Waf-Ua-Whitelisted"
	ChallengePassAfterFlag = "X-Waf-Challenge-Pass-After-Flag"
)

// RiskAssessment condensée du moteur de risque (FR-33).
const (
	RiskScore         = "X-Waf-Risk-Score"
	RiskDecision      = "X-Waf-Risk-Decision"
	RiskConfidence    = "X-Waf-Risk-Confidence"
	RiskDecisionBasis = "X-Waf-Risk-Decision-Basis"
	RiskCorroborated  = "X-Waf-Risk-Corroborated"
	RiskVerifiedBot   = "X-Waf-Risk-Verified-Bot"
	RiskShadowMode    = "X-Waf-Risk-Shadow-Mode"
)

// Contributions des familles de signaux au moteur de risque : RiskPrefix suivi
// du nom de la famille.
const (
	RiskPrefix      = "X-Waf-Risk-"
	RiskRate        = "X-Waf-Risk-Rate"
	RiskTLS         = "X-Waf-Risk-Tls"
	RiskIntegrity   = "X-Waf-Risk-Integrity"
	RiskGeo         = "X-Waf-Risk-Geo"
	RiskFingerprint = "X-Waf-Risk-Fingerprint"
	RiskBehavioral  = "X-Waf-Risk-Behavioral"
)

// ReasonStaticAsset est la raison du PASS posé par le bypass d'assets (FR-24).
// Ce PASS lève le challenge et le trust score, pas le rate limit : le rate
// limit et l'analyse comportementale le distinguent du PASS de la whitelist IP
// par cette raison, sans dépendre du package qui la pose.
const ReasonStaticAsset = "static_asset"

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
