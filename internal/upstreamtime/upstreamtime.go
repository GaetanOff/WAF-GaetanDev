// Package upstreamtime transporte, dans le contexte de requête, le temps passé
// à parler à l'upstream (round-trip + streaming de la réponse). Le proxy
// l'alimente ; le middleware de log le soustrait du temps total pour obtenir le
// temps réellement passé DANS le WAF (waf_latency_ms), distinct de la latence
// totale (latency_ms) qui inclut l'upstream.
package upstreamtime

import (
	"context"
	"sync/atomic"
	"time"
)

type contextKey struct{}

// Recorder cumule (de façon concurrente) le temps upstream d'une requête.
type Recorder struct {
	ns atomic.Int64
}

// Add ajoute une durée upstream. Sûr sur un Recorder nil (no-op).
func (r *Recorder) Add(d time.Duration) {
	if r == nil || d <= 0 {
		return
	}
	r.ns.Add(int64(d))
}

// Total retourne le temps upstream cumulé. 0 sur un Recorder nil.
func (r *Recorder) Total() time.Duration {
	if r == nil {
		return 0
	}
	return time.Duration(r.ns.Load())
}

// WithRecorder attache un nouveau Recorder au contexte et le retourne.
func WithRecorder(ctx context.Context) (context.Context, *Recorder) {
	r := &Recorder{}
	return context.WithValue(ctx, contextKey{}, r), r
}

// FromContext récupère le Recorder du contexte (nil s'il n'y en a pas).
func FromContext(ctx context.Context) *Recorder {
	recorder, _ := ctx.Value(contextKey{}).(*Recorder)
	return recorder
}
