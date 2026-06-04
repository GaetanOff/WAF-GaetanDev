package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	defaultListenAddress = ":8080"
	shutdownTimeout      = 15 * time.Second
)

func main() {
	if err := run(); err != nil {
		slog.Error("waf stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	listenAddress := flag.String("listen", defaultListenAddress, "public HTTP listen address")
	flag.Parse()

	server := &http.Server{
		Addr:              *listenAddress,
		Handler:           routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errs := make(chan error, 1)
	go func() {
		slog.Info("starting waf", "listen", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
			return
		}
		errs <- nil
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)

	select {
	case signalReceived := <-stop:
		slog.Info("shutdown requested", "signal", signalReceived.String())
	case err := <-errs:
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown server: %w", err)
	}

	return <-errs
}

func routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/waf/health", healthHandler)
	return mux
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
