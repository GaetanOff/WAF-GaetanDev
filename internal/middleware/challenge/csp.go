package challenge

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

// cspNonceBytes : 128 bits d'aléa, le minimum recommandé par CSP Level 3.
const cspNonceBytes = 16

// newCSPNonce tire le nonce d'une réponse. crypto/rand.Read n'échoue pas
// (Go ≥ 1.24 : il interrompt le processus plutôt que de rendre une erreur).
func newCSPNonce() string {
	nonce := make([]byte, cspNonceBytes)
	_, _ = rand.Read(nonce)
	return base64.RawURLEncoding.EncodeToString(nonce)
}

// setPageCSP pose la Content-Security-Policy de la page de challenge (FR-06) :
// seuls son script et son style inline, marqués du nonce, s'exécutent, et la
// page ne joint que /waf/verify. Défense en profondeur de l'échappement de
// html/template : la page s'affiche sur tous les domaines protégés. Posée avant
// secheaders, elle prime sur une security_headers.content_security_policy
// (injectée seulement en l'absence de l'en-tête).
func setPageCSP(w http.ResponseWriter, nonce string) {
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; "+
			"connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
}
