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

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/proxy"
)

const (
	defaultConfigPath = "configs/config.example.yaml"
)

func main() {
	if err := run(); err != nil {
		slog.Error("waf stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", defaultConfigPath, "config YAML path")
	listenAddress := flag.String("listen", "", "override public HTTP listen address")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *listenAddress != "" {
		cfg.Server.Listen = *listenAddress
	}

	readTimeout, err := parseDuration("server.read_timeout", cfg.Server.ReadTimeout)
	if err != nil {
		return err
	}
	writeTimeout, err := parseDuration("server.write_timeout", cfg.Server.WriteTimeout)
	if err != nil {
		return err
	}
	idleTimeout, err := parseDuration("server.idle_timeout", cfg.Server.IdleTimeout)
	if err != nil {
		return err
	}
	shutdownTimeout, err := parseDuration("server.graceful_shutdown_timeout", cfg.Server.GracefulShutdownTimeout)
	if err != nil {
		return err
	}

	proxyHandler, err := proxy.NewHandler(*cfg)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           routes(*cfg, proxyHandler),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
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

func routes(cfg config.Config, proxyHandler http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/waf/health", healthHandler)
	if cfg.Cloudflare.Trusted {
		proxyHandler = cloudflare.Middleware(proxyHandler)
	}
	mux.Handle("/", proxyHandler)
	return mux
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func parseDuration(field string, value string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid Go duration: %w", field, err)
	}

	return duration, nil
}
