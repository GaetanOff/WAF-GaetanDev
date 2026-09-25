package main

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
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

// fakeServer enregistre l'état du contexte reçu par Shutdown ; slow bloque
// jusqu'à l'expiration du délai de grâce, comme un serveur qui draine.
type fakeServer struct {
	slow       bool
	called     atomic.Bool
	ctxExpired atomic.Bool
}

func (f *fakeServer) Shutdown(ctx context.Context) error {
	f.called.Store(true)
	f.ctxExpired.Store(ctx.Err() != nil)
	if f.slow {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

// Un serveur qui consomme tout le délai de grâce ne prive pas les autres du
// leur : tous reçoivent un contexte encore valide.
func TestShutdownAllGivesEveryServerTheGracePeriod(t *testing.T) {
	slow, admin := &fakeServer{slow: true}, &fakeServer{}
	servers := []namedServer{{name: "public", server: slow}, {name: "admin", server: admin}}

	err := shutdownAll(servers, 50*time.Millisecond)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdownAll() = %v, want the public server deadline error", err)
	}
	if !admin.called.Load() || admin.ctxExpired.Load() {
		t.Fatalf("admin shutdown called=%v with expired context=%v, want a live context", admin.called.Load(), admin.ctxExpired.Load())
	}
}

// L'échec d'un listener arrête aussi les serveurs déjà démarrés, et c'est
// cette erreur qui est remontée.
func TestAwaitShutdownStopsEveryServerOnListenerFailure(t *testing.T) {
	public, admin := &fakeServer{}, &fakeServer{}
	servers := []namedServer{{name: "public", server: public}, {name: "admin", server: admin}}
	errs := make(chan error, maxListeners)
	boom := errors.New("address already in use")
	errs <- boom

	err := awaitShutdown(servers, errs, time.Second)

	if !errors.Is(err, boom) {
		t.Fatalf("awaitShutdown() = %v, want %v", err, boom)
	}
	if !public.called.Load() || !admin.called.Load() {
		t.Fatalf("shutdown called public=%v admin=%v, want both", public.called.Load(), admin.called.Load())
	}
}
