// Package origin protège le serveur d'origine (FR-19). Le WAF injecte dans
// chaque requête proxifiée un header X-WAF-Origin-Token = HMAC-SHA256(secret,
// domaine + heure courante), rotatif chaque heure avec une tolérance de 2 h.
// Un endpoint /waf/origin/verify permet à l'upstream de vérifier le token.
package origin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"
)

const (
	// HeaderToken est le header injecté vers l'upstream et vérifié par celui-ci.
	HeaderToken = "X-WAF-Origin-Token"

	toleranceHours = 2
)

// Signer génère et vérifie les tokens d'origine.
type Signer struct {
	secret []byte
	now    func() time.Time
}

func NewSigner(secret string) *Signer {
	return &Signer{secret: []byte(secret), now: time.Now}
}

// Token retourne le token courant pour un domaine (rotatif horaire).
func (s *Signer) Token(domain string) string {
	return s.tokenForHour(domain, s.now().Unix()/3600)
}

func (s *Signer) tokenForHour(domain string, hour int64) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(domain + ":" + strconv.FormatInt(hour, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify accepte le token de l'heure courante et des `toleranceHours` heures
// précédentes (rotation sans coupure).
func (s *Signer) Verify(domain string, token string) bool {
	currentHour := s.now().Unix() / 3600
	for delta := int64(0); delta <= toleranceHours; delta++ {
		expected := s.tokenForHour(domain, currentHour-delta)
		if hmac.Equal([]byte(expected), []byte(token)) {
			return true
		}
	}
	return false
}

// Injector pose le header X-WAF-Origin-Token sur la requête avant le proxy ;
// httputil.ReverseProxy le transmet alors à l'upstream.
func (s *Signer) Injector(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set(HeaderToken, s.Token(r.Host))
		next.ServeHTTP(w, r)
	})
}

// VerifyHandler répond à GET /waf/origin/verify : 200 si le token (header) est
// valide pour le domaine (query `domain` ou Host), 401 sinon. Destiné à être
// appelé par l'upstream.
func (s *Signer) VerifyHandler(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		domain = r.Host
	}
	if s.Verify(domain, r.Header.Get(HeaderToken)) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"valid":true}`))
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"valid":false}`))
}
