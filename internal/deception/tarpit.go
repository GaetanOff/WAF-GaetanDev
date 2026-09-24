// Package deception implémente la couche de déception (FR-15). Le tarpit sert
// aux bots une fausse réponse HTML 200 envoyée par petits chunks espacés de
// délais, pour ralentir scrapers et outils d'attaque. Le nombre de connexions
// tarpitées simultanées est borné par un sémaphore (NFR-10) ; au-delà, la
// requête reçoit un 429 plutôt que d'épuiser les goroutines.
//
// L'injection de contenu honeypot dans les réponses proxifiées est différée ;
// la détection du suivi d'un chemin honeypot est déjà assurée par le middleware
// antibot (honeypot_paths).
package deception

import (
	"errors"
	"net/http"
	"strconv"
	"time"
)

const tarpitActionHeader = "X-WAF-Action"

// Tarpit ralentit les requêtes marquées TARPIT par le moteur de risque.
type Tarpit struct {
	sem    chan struct{}
	chunks int
	delay  time.Duration
}

func NewTarpit(maxConnections int, chunks int, delay time.Duration) *Tarpit {
	if maxConnections < 1 {
		maxConnections = 1
	}
	if chunks < 1 {
		chunks = 1
	}
	return &Tarpit{
		sem:    make(chan struct{}, maxConnections),
		chunks: chunks,
		delay:  delay,
	}
}

// Dispatch sert le tarpit lorsque la requête a été classée TARPIT par le moteur
// de risque, sinon transmet à next (le proxy).
func (t *Tarpit) Dispatch(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(tarpitActionHeader) != "TARPIT" {
			next.ServeHTTP(w, r)
			return
		}

		select {
		case t.sem <- struct{}{}:
			defer func() { <-t.sem }()
			t.serve(w, r)
		default:
			// Sémaphore plein : on protège les goroutines (NFR-10).
			w.Header().Set("Retry-After", "5")
			http.Error(w, "service unavailable", http.StatusTooManyRequests)
		}
	})
}

// serve écrit une fausse page HTML par chunks espacés de délais.
func (t *Tarpit) serve(w http.ResponseWriter, r *http.Request) {
	// ResponseController remonte la chaîne Unwrap() : les middlewares en amont
	// (métriques, journal, anti-DDoS) enveloppent w sans implémenter
	// http.Flusher, et une assertion directe w.(http.Flusher) échouait donc
	// toujours. La réponse était alors bufférisée et envoyée d'un bloc à la fin
	// du délai, au lieu de retenir le client chunk par chunk.
	controller := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	parts := []string{
		"<!doctype html><html><head><title>Loading…</title></head><body>",
		"<h1>Please wait</h1><p>Your request is being processed",
	}
	for i := 0; i < t.chunks; i++ {
		var chunk string
		switch {
		case i < len(parts):
			chunk = parts[i]
		case i == t.chunks-1:
			chunk = "</p></body></html>"
		default:
			chunk = "<span style=\"display:none\">" + strconv.Itoa(i) + "</span>"
		}
		if _, err := w.Write([]byte(chunk)); err != nil {
			return
		}
		if err := controller.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return
		}
		select {
		case <-time.After(t.delay):
		case <-r.Context().Done():
			return
		}
	}
}
