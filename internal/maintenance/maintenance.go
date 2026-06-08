// Package maintenance fournit le mode maintenance et les pages d'erreur
// personnalisées (FR-32) : pages HTML brandées « Protected by GaetanDev.fr »,
// sans ressource externe. En mode maintenance, toutes les requêtes (hors
// endpoints internes) reçoivent une page 503 ; sinon, les corps d'erreur en
// texte brut sont remplacés par une page HTML brandée.
package maintenance

import (
	"net/http"
	"strconv"

	"github.com/gaetandev/waf/internal/config"
)

var bypassPaths = map[string]struct{}{
	"/waf/health":  {},
	"/waf/metrics": {},
}

// Middleware applique le mode maintenance et/ou les pages d'erreur brandées.
type Middleware struct {
	maintenance bool
	errorPages  bool
}

func New(cfg config.Maintenance) Middleware {
	return Middleware{maintenance: cfg.Enabled, errorPages: cfg.ErrorPages}
}

func (m Middleware) Handler(next http.Handler) http.Handler {
	if !m.maintenance && !m.errorPages {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.maintenance {
			if _, internal := bypassPaths[r.URL.Path]; !internal {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Retry-After", "300")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(page("Maintenance en cours", "Le service est temporairement indisponible. Merci de réessayer dans quelques minutes.")))
				return
			}
		}
		if m.errorPages {
			next.ServeHTTP(&pageWriter{ResponseWriter: w}, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// pageWriter remplace le corps des réponses d'erreur (4xx/5xx) en texte brut
// par une page HTML brandée. Les réponses déjà HTML sont préservées.
type pageWriter struct {
	http.ResponseWriter
	wroteHeader bool
	replaced    bool
}

func (w *pageWriter) WriteHeader(statusCode int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	if statusCode >= 400 && !isHTML(w.Header().Get("Content-Type")) {
		title, msg := messageFor(statusCode)
		body := page(title, msg)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.ResponseWriter.WriteHeader(statusCode)
		_, _ = w.ResponseWriter.Write([]byte(body))
		w.replaced = true
		return
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *pageWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.replaced {
		return len(b), nil // corps d'origine ignoré (remplacé par la page brandée)
	}
	return w.ResponseWriter.Write(b)
}

func (w *pageWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func isHTML(contentType string) bool {
	return len(contentType) >= 9 && contentType[:9] == "text/html"
}

func messageFor(status int) (string, string) {
	switch status {
	case http.StatusForbidden:
		return "Accès refusé", "Votre requête a été bloquée par le pare-feu applicatif."
	case http.StatusTooManyRequests:
		return "Trop de requêtes", "Vous avez envoyé trop de requêtes. Merci de patienter avant de réessayer."
	case http.StatusServiceUnavailable:
		return "Service indisponible", "Le service est temporairement indisponible. Merci de réessayer."
	case http.StatusBadGateway:
		return "Passerelle invalide", "Le serveur d'origine est injoignable pour le moment."
	default:
		return "Erreur", "Une erreur est survenue lors du traitement de votre requête."
	}
}

// page rend une page HTML brandée, sans ressource externe (CSS inline).
func page(title string, message string) string {
	return `<!doctype html><html lang="fr"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width, initial-scale=1">` +
		`<title>` + title + `</title><style>` +
		`body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;` +
		`font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0}` +
		`.card{max-width:32rem;padding:2rem;text-align:center}` +
		`h1{font-size:1.5rem;margin:0 0 1rem}p{color:#94a3b8;line-height:1.6}` +
		`.brand{margin-top:2rem;font-size:.8rem;color:#64748b}` +
		`.brand a{color:#38bdf8;text-decoration:none}</style></head><body><div class="card">` +
		`<h1>` + title + `</h1><p>` + message + `</p>` +
		`<div class="brand">Protected by <a href="https://firewall.gaetandev.fr">GaetanDev.fr</a></div>` +
		`</div></body></html>`
}
