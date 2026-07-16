// Package maintenance fournit le mode maintenance et les pages d'erreur
// personnalisées (FR-32) : pages HTML brandées « Protected by GaetanDev.fr »,
// sans ressource externe. En mode maintenance, toutes les requêtes (hors
// endpoints internes) reçoivent une page 503 ; sinon, les corps d'erreur en
// texte brut sont remplacés par une page HTML brandée.
package maintenance

import (
	"net/http"
	"strconv"
	"strings"

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
		// Les pages d'erreur brandées ne concernent que les navigations de
		// navigateur (Accept: text/html). Les appels API/XHR (fetch, axios…)
		// attendent le corps d'origine (souvent JSON) : on ne le remplace pas,
		// sinon le client ne peut plus parser la réponse d'erreur.
		if m.errorPages && wantsHTML(r) {
			next.ServeHTTP(&pageWriter{ResponseWriter: w}, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// wantsHTML indique que le client attend une page HTML (navigation navigateur),
// par opposition à un appel API/XHR.
func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// pageWriter remplace le corps des réponses d'erreur (4xx/5xx) par une page HTML
// brandée. Les 4xx déjà en HTML sont préservés (page/JSON légitime d'appli) ;
// les 5xx sont brandés même en HTML (cf. shouldReplace).
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
	if shouldReplace(statusCode, w.Header().Get("Content-Type")) {
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

// shouldReplace décide si le corps d'erreur doit être remplacé par la page
// brandée. Les 5xx sont TOUJOURS brandés (même en HTML) : un 502/503/504 vient
// d'une passerelle/origine en panne — c'est une page d'erreur générique d'un
// reverse proxy en aval (nginx/OpenResty), pas du contenu applicatif à préserver.
// Les 4xx ne sont brandés que si le corps n'est pas déjà du HTML, afin de
// préserver les pages d'erreur ou le JSON légitimes des applications.
func shouldReplace(status int, contentType string) bool {
	if status >= 500 {
		return true
	}
	if status >= 400 {
		return !isHTML(contentType)
	}
	return false
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
//
// Le design suit la page de challenge / d'accès autorisé (carte centrée, badge
// « Protected by GaetanDev.fr », dark mode auto — cf. maintenance-page.feature :
// « visuellement cohérente avec la page de challenge »). L'icône est une croix
// rouge animée (pop du cercle + tracé du trait), miroir de la coche verte de la
// page d'accès autorisé, pour signaler un blocage/erreur.
func page(title string, message string) string {
	return `<!doctype html><html lang="fr"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width, initial-scale=1">` +
		`<title>` + title + `</title><style>` +
		`:root{--accent:rgb(220,38,38);--accent-soft:rgba(220,38,38,.12);` +
		`--bg:#f0f0f0;--card:#fff;--text:#333;--muted:#888;--shadow:0 0 20px rgba(0,0,0,.1)}` +
		`@media (prefers-color-scheme:dark){:root{--bg:#121212;--card:#1e1e1e;` +
		`--text:#f0f0f0;--muted:#9a9a9a;--shadow:0 0 20px rgba(0,0,0,.6)}}` +
		`*{box-sizing:border-box}` +
		`body{font-family:Arial,sans-serif;margin:0;padding:0;background:var(--bg);color:var(--text);` +
		`display:flex;justify-content:center;align-items:center;min-height:100vh}` +
		`.card{text-align:center;padding:32px 28px 28px;border-radius:10px;box-shadow:var(--shadow);` +
		`background:var(--card);max-width:420px;width:calc(100% - 32px)}` +
		`.cross-wrap{width:72px;height:72px;margin:0 auto 20px;border-radius:50%;background:var(--accent-soft);` +
		`display:flex;align-items:center;justify-content:center;` +
		`animation:pop .5s cubic-bezier(.18,.89,.32,1.28) both}` +
		`@keyframes pop{0%{transform:scale(0);opacity:0}100%{transform:scale(1);opacity:1}}` +
		`.cross-wrap svg{width:40px;height:40px}` +
		`.cross-wrap path{stroke:var(--accent);stroke-width:5;stroke-linecap:round;stroke-linejoin:round;` +
		`fill:none;stroke-dasharray:57;stroke-dashoffset:57;animation:draw .5s .35s ease-out forwards}` +
		`@keyframes draw{to{stroke-dashoffset:0}}` +
		`.header{font-size:24px;font-weight:bold;color:var(--text);margin:0 0 8px}` +
		`.subtitle{font-size:15px;color:var(--muted);margin:0;line-height:1.5}` +
		`.footer-badge{position:fixed;bottom:10px;left:50%;transform:translateX(-50%);background:var(--card);` +
		`border-radius:8px;padding:4px 12px;font-size:12px;color:var(--text);box-shadow:0 0 6px rgba(0,0,0,.1)}` +
		`@media (prefers-color-scheme:dark){.footer-badge{box-shadow:0 0 6px rgba(0,0,0,.6)}}` +
		`.footer-badge a{color:var(--accent);font-weight:bold;text-decoration:none}` +
		`@media (prefers-reduced-motion:reduce){.cross-wrap,.cross-wrap path{animation:none}` +
		`.cross-wrap path{stroke-dashoffset:0}.cross-wrap{opacity:1;transform:none}}` +
		`</style></head><body>` +
		`<div class="card">` +
		`<div class="cross-wrap" role="img" aria-label="` + title + `">` +
		`<svg viewBox="0 0 60 60"><path d="M20 20 L40 40 M40 20 L20 40"/></svg></div>` +
		`<h1 class="header">` + title + `</h1>` +
		`<p class="subtitle">` + message + `</p>` +
		`</div>` +
		`<div class="footer-badge">Protected by ` +
		`<a href="https://firewall.gaetandev.fr" target="_blank" rel="noopener">GaetanDev.fr</a></div>` +
		`</body></html>`
}
