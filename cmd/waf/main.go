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

	"github.com/gaetandev/waf/internal/admin"
	"github.com/gaetandev/waf/internal/behavioral"
	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/integrity"
	waflogger "github.com/gaetandev/waf/internal/logger"
	wafmetrics "github.com/gaetandev/waf/internal/metrics"
	"github.com/gaetandev/waf/internal/middleware/access"
	"github.com/gaetandev/waf/internal/middleware/antibot"
	"github.com/gaetandev/waf/internal/middleware/antiddos"
	"github.com/gaetandev/waf/internal/middleware/challenge"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/middleware/ratelimit"
	"github.com/gaetandev/waf/internal/proxy"
	"github.com/gaetandev/waf/internal/risk"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/trust"
)

const (
	defaultConfigPath     = "configs/config.example.yaml"
	defaultHealthCheckURL = "http://127.0.0.1:8080/waf/health"
)

func main() {
	if err := run(); err != nil {
		slog.Error("waf stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	startedAt := time.Now()
	configPath := flag.String("config", defaultConfigPath, "config YAML path")
	listenAddress := flag.String("listen", "", "override public HTTP listen address")
	healthCheck := flag.Bool("healthcheck", false, "probe the health endpoint and exit (for container HEALTHCHECK)")
	healthCheckURL := flag.String("health-url", defaultHealthCheckURL, "health endpoint URL probed by -healthcheck")
	flag.Parse()

	if *healthCheck {
		return runHealthCheck(*healthCheckURL)
	}

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
	accessRules, err := access.NewRuleSet(cfg.Whitelist, cfg.Blacklist, cfg.WhitelistUserAgents)
	if err != nil {
		return err
	}
	store := memory.New(cfg.Trust.MaxVisitors)
	defer store.Close()
	scoreManager, err := trust.NewScoreManager(store, *cfg)
	if err != nil {
		return err
	}
	antiDDoS, err := antiddos.NewFromConfig(store, *cfg)
	if err != nil {
		return err
	}
	rateLimiter, err := ratelimit.New(store, scoreManager, *cfg)
	if err != nil {
		return err
	}
	antiBot := antibot.New(antibot.NewRules(*cfg), scoreManager)
	riskMiddleware, err := risk.NewMiddleware(store, scoreManager, *cfg)
	if err != nil {
		return err
	}
	// Détecteurs avancés : publient des contributions de signal consommées par le
	// moteur de risque ; exécutés juste avant lui (Phase 8).
	detectors := []func(http.Handler) http.Handler{
		integrity.NewAnalyzer(*cfg).Handler,
	}
	if cfg.Behavioral.Enabled {
		behavioralTracker := behavioral.New(cfg.Behavioral.MaxRecords)
		defer behavioralTracker.Close()
		detectors = append(detectors, behavioralTracker.Handler)
	}
	challengeMiddleware, err := challenge.NewMiddleware(*cfg, scoreManager, "web/challenge.html")
	if err != nil {
		return err
	}
	securityLogger := waflogger.New(cfg.Logging)
	metrics := wafmetrics.New()

	server := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           routes(*cfg, accessRules, securityLogger, metrics, antiDDoS, rateLimiter, antiBot, riskMiddleware, challengeMiddleware, scoreManager, detectors, proxyHandler),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
	var adminServer *admin.Server
	if cfg.Admin.Enabled {
		adminServer, err = admin.NewServer(*cfg, store, scoreManager, accessRules, startedAt)
		if err != nil {
			return err
		}
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
	if adminServer != nil {
		go func() {
			slog.Info("starting admin api", "listen", cfg.Server.AdminListen)
			if err := adminServer.ListenAndServe(); err != nil {
				errs <- err
			}
		}()
	}

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
	if adminServer != nil {
		if err := adminServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutdown admin server: %w", err)
		}
	}

	return <-errs
}

func routes(cfg config.Config, accessRules *access.RuleSet, securityLogger waflogger.Logger, metrics *wafmetrics.Metrics, antiDDoS antiddos.Middleware, rateLimiter *ratelimit.Middleware, antiBot antibot.Middleware, riskMiddleware *risk.Middleware, challengeMiddleware challenge.Middleware, scoreManager *trust.ScoreManager, detectors []func(http.Handler) http.Handler, proxyHandler http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/waf/health", healthHandler)
	mux.Handle("/waf/metrics", metrics.Handler())
	if cfg.RiskEngine.Enabled && riskMiddleware != nil {
		proxyHandler = riskMiddleware.Handler(proxyHandler)
	} else {
		proxyHandler = scoreManager.Middleware(proxyHandler)
	}
	// Détecteurs avancés exécutés juste avant le moteur de risque (wrap en ordre
	// inverse pour préserver l'ordre d'exécution detectors[0], detectors[1], ...).
	for i := len(detectors) - 1; i >= 0; i-- {
		proxyHandler = detectors[i](proxyHandler)
	}
	proxyHandler = antiBot.Handler(proxyHandler)
	if cfg.RateLimit.Enabled {
		proxyHandler = rateLimiter.Handler(proxyHandler)
	}
	if cfg.Challenge.Enabled {
		proxyHandler = challengeMiddleware.Handler(proxyHandler)
	}
	proxyHandler = antiDDoS.Handler(proxyHandler)
	proxyHandler = access.Middleware(accessRules, proxyHandler)
	if cfg.Cloudflare.Trusted {
		proxyHandler = securityLogger.Middleware(scoreManager, proxyHandler)
		proxyHandler = metrics.Middleware(scoreManager, proxyHandler)
		proxyHandler = cloudflare.Middleware(proxyHandler)
	} else {
		proxyHandler = securityLogger.Middleware(scoreManager, proxyHandler)
		proxyHandler = metrics.Middleware(scoreManager, proxyHandler)
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

// runHealthCheck probes the health endpoint and returns an error on any
// non-200 response. It powers the container HEALTHCHECK without requiring a
// shell or curl in the (distroless/scratch) runtime image.
func runHealthCheck(url string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("healthcheck request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck status %d", response.StatusCode)
	}
	return nil
}
