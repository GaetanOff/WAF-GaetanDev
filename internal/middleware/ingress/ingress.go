// Package ingress assainit les requêtes entrantes avant tout autre middleware.
//
// Les middlewares du WAF se coordonnent via des en-têtes `X-WAF-*` posés sur la
// requête (`X-WAF-Action: PASS` marque un bypass décidé par la whitelist ou le
// bypass d'assets statiques ; `X-WAF-Score-Delta`, `X-WAF-Risk-*`, etc. portent
// l'état du moteur de risque). Ces en-têtes sont de l'état interne : ils doivent
// provenir du pipeline, jamais du client.
//
// Sans ce nettoyage, un client qui envoie lui-même `X-WAF-Action: PASS`
// court-circuite le challenge, le rate limiting, l'analyse d'intégrité, le
// threat intel et le moteur de règles — un contournement complet du WAF en un
// seul en-tête. Le préfixe entier est supprimé (et non une liste nominative)
// pour rester correct si de nouveaux en-têtes internes sont ajoutés.
package ingress

import (
	"net/http"
	"strings"
)

// headerPrefix est le préfixe des en-têtes internes, comparé sans tenir compte
// de la casse.
const headerPrefix = "X-WAF-"

// Middleware supprime tout en-tête `X-WAF-*` fourni par le client. Il doit
// précéder tout middleware qui lit ces en-têtes. Une seule capture est autorisée
// en amont : le token FR-19 retransmis à /waf/origin/verify (voir
// origin.CaptureInboundToken), qui n'est pas interprété mais seulement mémorisé.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name := range r.Header {
			// net/http canonicalise les clés issues du fil, mais la comparaison
			// reste insensible à la casse : la protection ne doit pas dépendre
			// d'un invariant interne de la bibliothèque. Supprimer pendant le
			// parcours est défini par la spécification du langage.
			if len(name) >= len(headerPrefix) && strings.EqualFold(name[:len(headerPrefix)], headerPrefix) {
				delete(r.Header, name)
			}
		}

		next.ServeHTTP(w, r)
	})
}
