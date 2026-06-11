package logger

import (
	"io"
	"sync/atomic"
)

// asyncBufferSize est la capacité du tampon d'événements en attente d'écriture.
const asyncBufferSize = 8192

// asyncWriter découple l'écriture des logs du chemin de requête (FR-09, NFR-16).
// Write copie la ligne et l'empile dans un tampon ; un goroutine de fond réalise
// l'écriture réelle (bloquante) vers la sortie. Si le tampon est plein — par ex.
// quand le consommateur de stdout ralentit (rotation Docker json-file, disque
// saturé, `docker logs` non lu) — la ligne est ABANDONNÉE (compteur dropped)
// plutôt que de bloquer le goroutine appelant.
//
// Sans ce découplage, une écriture stdout bloquée fige le goroutine de requête
// dans le middleware de log (le plus externe), donc la connexion keep-alive
// n'est pas libérée pour la requête suivante, ce qui provoque des timeouts en
// cascade côté Cloudflare (pool de connexions partagé vers l'origine).
type asyncWriter struct {
	out     io.Writer
	queue   chan []byte
	dropped atomic.Int64
	done    chan struct{}
	flushed chan struct{}
}

func newAsyncWriter(out io.Writer, buffer int) *asyncWriter {
	if buffer < 1 {
		buffer = 1
	}
	w := &asyncWriter{
		out:     out,
		queue:   make(chan []byte, buffer),
		done:    make(chan struct{}),
		flushed: make(chan struct{}),
	}
	go w.run()
	return w
}

// Write n'écrit jamais directement : il copie (slog réutilise son tampon après
// le retour) puis enfile sans bloquer. Tampon plein → drop.
func (w *asyncWriter) Write(p []byte) (int, error) {
	line := make([]byte, len(p))
	copy(line, p)
	select {
	case w.queue <- line:
	default:
		w.dropped.Add(1)
	}
	return len(p), nil
}

func (w *asyncWriter) run() {
	defer close(w.flushed)
	for {
		select {
		case line := <-w.queue:
			_, _ = w.out.Write(line)
		case <-w.done:
			// Drain best-effort des lignes déjà en file avant de sortir.
			for {
				select {
				case line := <-w.queue:
					_, _ = w.out.Write(line)
				default:
					return
				}
			}
		}
	}
}

// Close arrête le goroutine de fond après avoir vidé la file (arrêt gracieux).
func (w *asyncWriter) Close() error {
	select {
	case <-w.done:
	default:
		close(w.done)
	}
	<-w.flushed
	return nil
}

// Dropped retourne le nombre de lignes de log abandonnées faute de place dans le
// tampon (consommateur de sortie trop lent). Sert au diagnostic.
func (w *asyncWriter) Dropped() int64 {
	return w.dropped.Load()
}
