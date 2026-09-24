package challenge

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gaetandev/waf/internal/config"
	browserfp "github.com/gaetandev/waf/internal/fingerprint"
	"github.com/gaetandev/waf/internal/jsonstrict"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/trust"
)

const (
	verifyPath = "/waf/verify"

	headerAction    = "X-WAF-Action"
	actionPass      = "PASS"
	actionChallenge = "CHALLENGE"
	// headerFingerprintHash transmet au moteur de risque le fingerprint lié au
	// cookie de clearance (preuve « fingerprint stable », FR-37).
	headerFingerprintHash = "X-WAF-Fingerprint-Hash"
)

type Middleware struct {
	tokenIssuer  TokenIssuer
	cookieIssuer CookieIssuer
	scores       *trust.ScoreManager
	template     *template.Template
	domains      domainGate
	cookieTTL    time.Duration
	difficulty   int
	difficultyFn func() int
	minElapsedMS int
	maxElapsedMS int
	humanCredit  func(ip string, domain string, fpHash string)
}

// WithHumanCredit branche l'enregistrement de la preuve humaine (FR-37) sur un
// challenge réussi. Sans elle, le moteur de risque ne voit jamais la preuve et
// un humain challengé par lui le serait de nouveau après avoir réussi.
func (m Middleware) WithHumanCredit(fn func(ip string, domain string, fpHash string)) Middleware {
	m.humanCredit = fn
	return m
}

// WithDifficultyProvider branche un fournisseur de difficulté adaptative
// (FR-14). En son absence, la difficulté statique de config est utilisée.
func (m Middleware) WithDifficultyProvider(fn func() int) Middleware {
	m.difficultyFn = fn
	return m
}

// currentDifficulty retourne la difficulté adaptative si fournie, sinon la
// difficulté statique de configuration.
func (m Middleware) currentDifficulty() int {
	if m.difficultyFn != nil {
		if d := m.difficultyFn(); d > 0 {
			return d
		}
	}
	return m.difficulty
}

type PageData struct {
	Token       string
	Difficulty  int
	RedirectURL string
}

type Submission struct {
	Token       string                `json:"token"`
	Nonce       string                `json:"nonce"`
	ElapsedMS   int                   `json:"elapsed_ms"`
	Fingerprint browserfp.Fingerprint `json:"fingerprint"`
}

type verifyResponse struct {
	RedirectURL string `json:"redirect_url"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// NewMiddleware charge le template depuis un fichier. Le binaire utilise
// NewMiddlewareFromSource avec la page embarquée (package web) ; ce
// constructeur sert à éprouver un template alternatif.
func NewMiddleware(cfg config.Config, scores *trust.ScoreManager, templatePath string) (Middleware, error) {
	content, err := os.ReadFile(templatePath)
	if err != nil {
		return Middleware{}, fmt.Errorf("read challenge template: %w", err)
	}
	return NewMiddlewareFromSource(cfg, scores, string(content))
}

// NewMiddlewareFromSource construit le middleware depuis le texte du template.
func NewMiddlewareFromSource(cfg config.Config, scores *trust.ScoreManager, source string) (Middleware, error) {
	pageTemplate, err := template.New("challenge").Parse(source)
	if err != nil {
		return Middleware{}, fmt.Errorf("parse challenge template: %w", err)
	}
	return NewMiddlewareFromTemplate(cfg, scores, pageTemplate)
}

func NewMiddlewareFromTemplate(cfg config.Config, scores *trust.ScoreManager, pageTemplate *template.Template) (Middleware, error) {
	tokenTTL, err := time.ParseDuration(cfg.Challenge.TokenTTL)
	if err != nil {
		return Middleware{}, fmt.Errorf("parse challenge.token_ttl: %w", err)
	}
	cookieTTL, err := time.ParseDuration(cfg.Challenge.CookieTTL)
	if err != nil {
		return Middleware{}, fmt.Errorf("parse challenge.cookie_ttl: %w", err)
	}
	return Middleware{
		tokenIssuer:  NewTokenIssuer(cfg.Challenge.SecretKey, tokenTTL),
		cookieIssuer: NewCookieIssuer(cfg.Challenge.CookieName, cfg.Challenge.SecretKey),
		scores:       scores,
		template:     pageTemplate,
		domains:      newDomainGate(cfg),
		cookieTTL:    cookieTTL,
		difficulty:   cfg.Challenge.PowDifficulty,
		minElapsedMS: cfg.Challenge.MinElapsedMS,
		maxElapsedMS: cfg.Challenge.MaxElapsedMS,
	}, nil
}

func (m Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == verifyPath {
			m.verify(w, r)
			return
		}
		// Surcharge par domaine (FR-06) : évaluée avant toute autre décision, y
		// compris le mode « sous attaque ». /waf/verify reste servi au-dessus :
		// "/waf/" est un préfixe réservé au WAF sur tous les domaines.
		if !m.domains.enabledFor(r.Host) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get(headerAction) == actionPass {
			next.ServeHTTP(w, r)
			return
		}
		if clearance, ok := m.clearance(r); ok {
			r.Header.Set(headerFingerprintHash, clearance.FPHash)
			next.ServeHTTP(w, r)
			return
		}
		// Le challenge JS n'a de sens que pour une navigation de navigateur (page
		// HTML de premier niveau). Les appels API/XHR (fetch, axios, mobile…) ne
		// peuvent pas exécuter le JS : on ne les challenge pas, sinon ils cassent.
		// Ils restent couverts par le reste de la chaîne (rate-limit, risk engine…).
		underAttack := r.Header.Get("X-WAF-Under-Attack-Enforce") == "true"
		if !shouldChallenge(r, underAttack) {
			next.ServeHTTP(w, r)
			return
		}
		m.servePage(w, r)
	})
}

// Enforcer sert la page de challenge aux requêtes que le moteur de risque
// (FR-34) ou le trust score (FR-04) ont classées CHALLENGE. Il se monte en aval
// de ces décisions, juste avant l'origine : Handler, lui, s'exécute avant elles
// et ne peut challenger que sur l'absence de clearance.
//
// Sans lui, une décision CHALLENGE n'était qu'un en-tête posé sur une requête
// transmise à l'upstream. Le visiteur sans clearance est déjà challengé par
// Handler : l'Enforcer vise donc le porteur d'un cookie valide que le moteur
// de risque ou le trust score jugent de nouveau suspect. Il est re-vérifié ;
// son succès alimente le crédit humain (WithHumanCredit), qui ramène la
// décision suivante à ALLOW et évite la boucle challenge → redirection →
// challenge. Comme devant Handler, un appel API/XHR n'est pas challengé : il
// ne peut pas exécuter le JS.
func (m Middleware) Enforcer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerAction) != actionChallenge || !m.domains.enabledFor(r.Host) {
			next.ServeHTTP(w, r)
			return
		}
		underAttack := r.Header.Get("X-WAF-Under-Attack-Enforce") == "true"
		if !shouldChallenge(r, underAttack) {
			next.ServeHTTP(w, r)
			return
		}
		m.servePage(w, r)
	})
}

func (m Middleware) verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var submission Submission
	if err := jsonstrict.Decode(r.Body, &submission); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_submission")
		return
	}
	if err := validateSubmission(submission); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_submission")
		return
	}

	ip := cloudflare.RealIP(r)
	payload, err := m.tokenIssuer.Validate(submission.Token, ip, r.Host)
	if err != nil {
		writeTokenError(w, err)
		return
	}
	powDifficulty := payload.Difficulty
	if powDifficulty <= 0 {
		powDifficulty = m.difficulty
	}
	if !ValidatePow(submission.Token, submission.Nonce, powDifficulty) {
		m.scores.Apply(ip, r.Host, trust.DeltaChallengeFailed)
		writeError(w, http.StatusBadRequest, "invalid_pow")
		return
	}
	if submission.ElapsedMS < m.minElapsedMS {
		m.scores.Apply(ip, r.Host, trust.DeltaChallengeFailed)
		writeError(w, http.StatusBadRequest, "challenge_too_fast")
		return
	}
	if submission.ElapsedMS > m.maxElapsedMS {
		writeError(w, http.StatusBadRequest, "challenge_timeout")
		return
	}
	parsedFingerprint, err := browserfp.Parse(submission.Fingerprint)
	if err != nil {
		if errors.Is(err, browserfp.ErrHeadlessRenderer) {
			m.scores.Apply(ip, r.Host, browserfp.HeadlessRendererDelta)
			writeError(w, http.StatusBadRequest, "headless_webgl_renderer")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_submission")
		return
	}

	visitor := m.scores.Apply(ip, r.Host, trust.DeltaChallengePassed)
	fpHash := fingerprintHash(browserfp.Hash(parsedFingerprint))
	cookie, err := m.cookieIssuer.Issue(ip, r.Host, fpHash, visitor.Score, m.cookieTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cookie_issue_failed")
		return
	}
	http.SetCookie(w, &cookie)
	if m.humanCredit != nil {
		m.humanCredit(ip, r.Host, fpHash)
	}
	redirectURL := payload.RedirectURL
	if redirectURL == "" {
		redirectURL = "/"
	}
	w.Header().Set("Content-Type", "application/json")
	setNoStore(w)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(verifyResponse{RedirectURL: redirectURL})
}

// clearance retourne le cookie de clearance de la requête s'il est valide
// (HMAC, TTL, IP, domaine).
func (m Middleware) clearance(r *http.Request) (*Payload, bool) {
	cookie, err := r.Cookie(m.cookieIssuer.Name)
	if err != nil {
		return nil, false
	}
	payload, err := m.cookieIssuer.Validate(cookie.Value, cloudflare.RealIP(r), r.Host)
	if err != nil {
		return nil, false
	}
	return payload, true
}

func (m Middleware) servePage(w http.ResponseWriter, r *http.Request) {
	redirectURL := r.URL.RequestURI()
	difficulty := m.currentDifficulty()
	token, err := m.tokenIssuer.GenerateForRedirectWithDifficulty(cloudflare.RealIP(r), r.Host, redirectURL, difficulty)
	if err != nil {
		http.Error(w, "challenge token error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Jamais mettre en cache : la page porte un token à durée de vie courte, lié
	// à l'IP. Un cache CDN (ex: règle Cloudflare "Cache Everything") figerait un
	// token expiré pour tous les visiteurs -> verify en échec -> boucle infinie.
	setNoStore(w)
	w.WriteHeader(http.StatusOK)
	_ = m.template.Execute(w, PageData{
		Token:       token,
		Difficulty:  difficulty,
		RedirectURL: redirectURL,
	})
}

// shouldChallenge décide si une requête sans clearance doit recevoir un challenge.
// En mode normal, seul un chargement de page navigateur est challengé. Sous attaque
// (FR-39), l'heuristique de navigation est relâchée pour délester un flood L7 dont
// les requêtes brutes n'envoient pas toujours "Accept: text/html".
func shouldChallenge(r *http.Request, underAttack bool) bool {
	if underAttack {
		return isChallengeableUnderAttack(r)
	}
	return isBrowserNavigation(r)
}

// isBrowserNavigation détecte une navigation de navigateur (chargement de page
// HTML), seul cas où servir un challenge JS a du sens. Un GET/HEAD dont l'en-tête
// Accept inclut "text/html" est une navigation ; les requêtes fetch/axios/XHR
// envoient "application/json" ou "*/*" et sont donc exclues du challenge.
func isBrowserNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// isChallengeableUnderAttack relâche l'heuristique de navigation sous mode sous
// attaque : tout GET/HEAD est challengeable (un vrai navigateur résout le PoW et
// obtient un cookie), SAUF s'il négocie explicitement un type non-HTML
// ("application/json") — un client API/XHR ne peut pas résoudre un challenge JS et
// reste couvert par le rate-limit et le moteur de risque.
func isChallengeableUnderAttack(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return !strings.Contains(r.Header.Get("Accept"), "application/json")
}

// setNoStore interdit toute mise en cache (navigateur et CDN) de la réponse.
func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func validateSubmission(submission Submission) error {
	if submission.Token == "" || submission.Nonce == "" {
		return errors.New("missing token or nonce")
	}
	if submission.ElapsedMS < 0 {
		return errors.New("negative elapsed_ms")
	}
	return nil
}

func writeTokenError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrTokenExpired):
		writeError(w, http.StatusBadRequest, "token_expired")
	case errors.Is(err, ErrTokenInvalid):
		writeError(w, http.StatusBadRequest, "invalid_token")
	default:
		writeError(w, http.StatusBadRequest, "invalid_token")
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	setNoStore(w)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: code})
}
