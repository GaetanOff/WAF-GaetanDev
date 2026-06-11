package logger

import (
	"sync"
	"testing"
	"time"
)

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// Le chemin de requête ne doit JAMAIS bloquer sur l'écriture de log : si la
// sortie est bloquée et le tampon plein, Write rend la main immédiatement et
// abandonne la ligne (compteur dropped).
func TestAsyncWriterDoesNotBlockOnSlowConsumer(t *testing.T) {
	release := make(chan struct{})
	blocking := writerFunc(func(p []byte) (int, error) {
		<-release // simule un stdout/disque bloqué
		return len(p), nil
	})
	w := newAsyncWriter(blocking, 4)

	done := make(chan struct{})
	go func() {
		for range 1000 {
			_, _ = w.Write([]byte("event\n"))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Write a bloqué sur un consommateur lent (le chemin de requête ne doit jamais bloquer)")
	}
	if w.Dropped() == 0 {
		t.Fatal("attendu des drops quand le consommateur est bloqué et le tampon plein")
	}

	close(release) // débloque l'écriture en cours puis arrête le worker
	_ = w.Close()
}

// En régime normal, toutes les lignes finissent par être écrites (drain au Close).
func TestAsyncWriterFlushesToConsumer(t *testing.T) {
	var mu sync.Mutex
	count := 0
	sink := writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		count++
		mu.Unlock()
		return len(p), nil
	})
	w := newAsyncWriter(sink, 16)

	for range 5 {
		_, _ = w.Write([]byte("line\n"))
	}
	_ = w.Close() // draine la file avant de rendre la main

	mu.Lock()
	defer mu.Unlock()
	if count != 5 {
		t.Fatalf("lignes écrites = %d, want 5", count)
	}
	if w.Dropped() != 0 {
		t.Fatalf("drops = %d, want 0 en régime normal", w.Dropped())
	}
}
