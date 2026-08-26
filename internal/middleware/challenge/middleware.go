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

const verifyPath = "/waf/verify"

type Middleware struct {
	tokenIssuer  TokenIssuer
	cookieIssuer CookieIssuer
	scores       *trust.ScoreManager
	template     *template.Template
	cookieTTL    time.Duration
	difficulty   int
	difficultyFn func() int
	minElapsedMS int
	maxElapsedMS int
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

func NewMiddleware(cfg config.Config, scores *trust.ScoreManager, templatePath string) (Middleware, error) {
	tokenTTL, err := time.ParseDuration(cfg.Challenge.TokenTTL)
	if err != nil {
		return Middleware{}, fmt.Errorf("parse challenge.token_ttl: %w", err)
	}
	cookieTTL, err := time.ParseDuration(cfg.Challenge.CookieTTL)
	if err != nil {
		return Middleware{}, fmt.Errorf("parse challenge.cookie_ttl: %w", err)
	}

	content, err := os.ReadFile(templatePath)
	if err != nil {
		return Middleware{}, fmt.Errorf("read challenge template: %w", err)
	}
	pageTemplate, err := template.New("challenge").Parse(string(content))
	if err != nil {
		return Middleware{}, fmt.Errorf("parse challenge template: %w", err)
	}

	return Middleware{
		tokenIssuer:  NewTokenIssuer(cfg.Challenge.SecretKey, tokenTTL),
		cookieIssuer: NewCookieIssuer(cfg.Challenge.CookieName, cfg.Challenge.SecretKey),
		scores:       scores,
		template:     pageTemplate,
		cookieTTL:    cookieTTL,
		difficulty:   cfg.Challenge.PowDifficulty,
		minElapsedMS: cfg.Challenge.MinElapsedMS,
		maxElapsedMS: cfg.Challenge.MaxElapsedMS,
	}, nil
}

func NewMiddlewareFromTemplate(cfg config.Config, scores *trust.ScoreManager, pageTemplate *template.Template) (Middleware, error) {
	tokenTTL, err := time.ParseDuration(cfg.Challenge.TokenTTL)
	if err != nil {
		return Middleware{}, err
	}
	cookieTTL, err := time.ParseDuration(cfg.Challenge.CookieTTL)
	if err != nil {
		return Middleware{}, err
	}
	return Middleware{
		tokenIssuer:  NewTokenIssuer(cfg.Challenge.SecretKey, tokenTTL),
		cookieIssuer: NewCookieIssuer(cfg.Challenge.CookieName, cfg.Challenge.SecretKey),
		scores:       scores,
		template:     pageTemplate,
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
		if r.Header.Get("X-WAF-Action") == "PASS" {
			next.ServeHTTP(w, r)
			return
		}
		if m.hasValidCookie(r) {
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
	cookie, err := m.cookieIssuer.Issue(ip, r.Host, browserfp.Hash(parsedFingerprint), visitor.Score, m.cookieTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cookie_issue_failed")
		return
	}
	http.SetCookie(w, &cookie)
	redirectURL := payload.RedirectURL
	if redirectURL == "" {
		redirectURL = "/"
	}
	w.Header().Set("Content-Type", "application/json")
	setNoStore(w)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(verifyResponse{RedirectURL: redirectURL})
}

func (m Middleware) hasValidCookie(r *http.Request) bool {
	cookie, err := r.Cookie(m.cookieIssuer.Name)
	if err != nil {
		return false
	}
	_, err = m.cookieIssuer.Validate(cookie.Value, cloudflare.RealIP(r), r.Host)
	return err == nil
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
