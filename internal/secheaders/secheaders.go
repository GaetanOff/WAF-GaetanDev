// Package secheaders injecte les en-têtes de sécurité (FR-21) et retire les
// en-têtes révélateurs (FR-22) sur les réponses. Les en-têtes déjà posés par
// l'upstream sont conservés (priorité upstream) ; ceux absents sont ajoutés.
package secheaders

import (
	"net/http"
	"strconv"

	"github.com/gaetandev/waf/internal/config"
)

// Middleware enrobe les réponses pour appliquer les en-têtes de sécurité et la
// sanitisation. Il s'installe le plus à l'extérieur du pipeline.
type Middleware struct {
	cfg config.SecurityHeaders
}

func New(cfg config.SecurityHeaders) Middleware {
	return Middleware{cfg: cfg}
}

func (m Middleware) Handler(next http.Handler) http.Handler {
	if !m.cfg.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&sanitizingWriter{ResponseWriter: w, cfg: m.cfg}, r)
	})
}

// sanitizingWriter applique en-têtes et sanitisation juste avant l'écriture des
// en-têtes de réponse (WriteHeader / premier Write).
type sanitizingWriter struct {
	http.ResponseWriter
	cfg     config.SecurityHeaders
	applied bool
}

func (w *sanitizingWriter) WriteHeader(statusCode int) {
	w.apply()
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *sanitizingWriter) Write(b []byte) (int, error) {
	w.apply()
	return w.ResponseWriter.Write(b)
}

func (w *sanitizingWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *sanitizingWriter) apply() {
	if w.applied {
		return
	}
	w.applied = true
	h := w.Header()

	// Sanitisation (FR-22) : retirer les en-têtes révélateurs.
	for _, name := range w.cfg.StripHeaders {
		h.Del(name)
	}

	// Injection si absent — priorité upstream (FR-21).
	if w.cfg.HSTSMaxAge > 0 {
		value := "max-age=" + strconv.Itoa(w.cfg.HSTSMaxAge)
		if w.cfg.HSTSIncludeSubdomains {
			value += "; includeSubDomains"
		}
		setIfAbsent(h, "Strict-Transport-Security", value)
	}
	if w.cfg.FrameOptions != "" {
		setIfAbsent(h, "X-Frame-Options", w.cfg.FrameOptions)
	}
	if w.cfg.ContentTypeNosniff {
		setIfAbsent(h, "X-Content-Type-Options", "nosniff")
	}
	if w.cfg.ReferrerPolicy != "" {
		setIfAbsent(h, "Referrer-Policy", w.cfg.ReferrerPolicy)
	}
	if w.cfg.PermissionsPolicy != "" {
		setIfAbsent(h, "Permissions-Policy", w.cfg.PermissionsPolicy)
	}
	if w.cfg.CSP != "" { // opt-in uniquement
		setIfAbsent(h, "Content-Security-Policy", w.cfg.CSP)
	}
}

func setIfAbsent(h http.Header, name string, value string) {
	if h.Get(name) == "" {
		h.Set(name, value)
	}
}
