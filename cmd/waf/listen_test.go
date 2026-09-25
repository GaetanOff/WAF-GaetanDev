package main

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

// Chaque serveur a sa place dans errs : quatre échecs simultanés au
// démarrage ne bloquent aucune goroutine, et un arrêt normal
// (http.ErrServerClosed) n'est pas remonté comme une erreur.
func TestListenInBackgroundReportsFailuresWithoutBlocking(t *testing.T) {
	errs := make(chan error, maxListeners)
	returned := make(chan struct{}, maxListeners+1)
	boom := errors.New("address already in use")
	listen := func(err error) func() error {
		return func() error {
			defer func() { returned <- struct{}{} }()
			return err
		}
	}

	listenInBackground(errs, listen(http.ErrServerClosed))
	for range maxListeners {
		listenInBackground(errs, listen(boom))
	}
	for range maxListeners + 1 {
		select {
		case <-returned:
		case <-time.After(2 * time.Second):
			t.Fatal("a listener goroutine did not return")
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for len(errs) < maxListeners && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := len(errs); got != maxListeners {
		t.Fatalf("reported errors = %d, want %d (ErrServerClosed excluded)", got, maxListeners)
	}
	for range maxListeners {
		if err := drainedError(errs); !errors.Is(err, boom) {
			t.Fatalf("drainedError() = %v, want %v", err, boom)
		}
	}
	if err := drainedError(errs); err != nil {
		t.Fatalf("drainedError() on an empty channel = %v, want nil", err)
	}
}
