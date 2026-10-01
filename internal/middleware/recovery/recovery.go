// Package recovery récupère le panic d'un handler de requête (NFR-04). La
// récupération de net/http protégeait le processus, mais journalisait sur
// stderr sans request_id, ne comptait rien et coupait la connexion sans
// réponse.
package recovery

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
)

const requestIDHeader = "X-Request-Id" // posé sur la réponse par le logger

// Middleware exécute next et, sur panic, journalise l'incident (request_id,
// méthode, chemin, pile), appelle onPanic puis répond avec respond si aucun
// en-tête n'est encore parti. Une réponse déjà entamée ne peut plus devenir un
// 500 : la connexion est interrompue, pour que le client ne prenne pas un
// corps tronqué pour complet. http.ErrAbortHandler est un abandon voulu (le
// reverse proxy l'emploie quand la copie du corps upstream échoue) : il est
// propagé tel quel.
func Middleware(next http.Handler, onPanic func(), respond http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracker := &headerTracker{ResponseWriter: w}
		defer func() {
			recovered := recover()
			if recovered == nil {
				return
			}
			if err, ok := recovered.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(recovered)
			}
			slog.Error("panic serving request",
				"panic", fmt.Sprint(recovered),
				"request_id", w.Header().Get(requestIDHeader),
				"method", r.Method,
				"path", r.URL.Path,
				"stack", string(debug.Stack()),
			)
			if onPanic != nil {
				onPanic()
			}
			if tracker.wroteHeader {
				panic(http.ErrAbortHandler)
			}
			respond(w, r)
		}()
		next.ServeHTTP(tracker, r)
	})
}

// PlainText est la réponse du listener public : texte brut, comme les autres
// refus du pipeline (les pages brandées FR-32 le remplacent pour un navigateur).
func PlainText(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

// headerTracker note qu'une réponse est entamée. Unwrap garde l'accès de
// http.ResponseController (Flush, Hijack du WebSocket) au writer d'origine.
type headerTracker struct {
	http.ResponseWriter
	wroteHeader bool
}

func (t *headerTracker) WriteHeader(statusCode int) {
	t.wroteHeader = true
	t.ResponseWriter.WriteHeader(statusCode)
}

func (t *headerTracker) Write(body []byte) (int, error) {
	t.wroteHeader = true
	return t.ResponseWriter.Write(body)
}

func (t *headerTracker) Unwrap() http.ResponseWriter {
	return t.ResponseWriter
}
