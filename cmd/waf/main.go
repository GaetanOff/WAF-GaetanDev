package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/gaetandev/waf/internal/acme"
	"github.com/gaetandev/waf/internal/adaptive"
	"github.com/gaetandev/waf/internal/admin"
	"github.com/gaetandev/waf/internal/alert"
	"github.com/gaetandev/waf/internal/behavioral"
	"github.com/gaetandev/waf/internal/cluster"
	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/deception"
	"github.com/gaetandev/waf/internal/geo"
	"github.com/gaetandev/waf/internal/integrity"
	waflogger "github.com/gaetandev/waf/internal/logger"
	"github.com/gaetandev/waf/internal/maintenance"
	wafmetrics "github.com/gaetandev/waf/internal/metrics"
	"github.com/gaetandev/waf/internal/middleware/access"
	"github.com/gaetandev/waf/internal/middleware/antibot"
	"github.com/gaetandev/waf/internal/middleware/antiddos"
	"github.com/gaetandev/waf/internal/middleware/challenge"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/middleware/ratelimit"
	"github.com/gaetandev/waf/internal/origin"
	"github.com/gaetandev/waf/internal/proxy"
	"github.com/gaetandev/waf/internal/risk"
	"github.com/gaetandev/waf/internal/rules"
	"github.com/gaetandev/waf/internal/secheaders"
	"github.com/gaetandev/waf/internal/selfprotect"
	"github.com/gaetandev/waf/internal/slowloris"
	"github.com/gaetandev/waf/internal/staticassets"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/threatintel"
	"github.com/gaetandev/waf/internal/tlsfp"
	"github.com/gaetandev/waf/internal/tlsmgr"
	"github.com/gaetandev/waf/internal/trust"
	"github.com/gaetandev/waf/internal/upstream"
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
	headerTimeout := 10 * time.Second
	if cfg.Slowloris.Enabled {
		headerTimeout, err = parseDuration("slowloris.header_timeout", cfg.Slowloris.HeaderTimeout)
		if err != nil {
			return err
		}
	}

	proxyHandler, err := proxy.NewHandler(*cfg)
	if err != nil {
		return err
	}
	// Pool d'upstreams + health checks + load balancing (FR-25/26).
	if cfg.UpstreamPool.Enabled {
		members := make([]*upstream.Upstream, 0, len(cfg.UpstreamPool.Upstreams))
		for _, u := range cfg.UpstreamPool.Upstreams {
			members = append(members, &upstream.Upstream{Address: u.Address, Weight: u.Weight, Backup: u.Backup})
		}
		pool := upstream.NewPool(cfg.UpstreamPool.Strategy, members)
		upstreamTimeout, err := parseDuration("upstream.timeout", cfg.Upstream.Timeout)
		if err != nil {
			return err
		}
		if err := proxyHandler.WithPool(pool, cfg.Upstream.TLSVerify, cfg.Upstream.MaxIdleConns, upstreamTimeout, cfg.Upstream.PreserveHost); err != nil {
			return err
		}
		hcInterval, err := parseDuration("upstream_pool.health_check.interval", cfg.UpstreamPool.HealthCheck.Interval)
		if err != nil {
			return err
		}
		hcTimeout, err := parseDuration("upstream_pool.health_check.timeout", cfg.UpstreamPool.HealthCheck.Timeout)
		if err != nil {
			return err
		}
		checker := upstream.NewHealthChecker(pool, cfg.UpstreamPool.HealthCheck.Path, hcInterval, hcTimeout, cfg.UpstreamPool.HealthCheck.HealthyThreshold, cfg.UpstreamPool.HealthCheck.UnhealthyThreshold)
		hcCtx, hcCancel := context.WithCancel(context.Background())
		defer hcCancel()
		checker.Start(hcCtx)
	}
	// originHandler est la cible finale du pipeline (proxy), éventuellement
	// précédée du tarpit (déception, FR-15) qui intercepte les requêtes classées
	// TARPIT par le moteur de risque avant qu'elles n'atteignent le proxy.
	var originHandler http.Handler = proxyHandler
	if cfg.Deception.Enabled {
		chunkDelay, err := parseDuration("deception.tarpit_chunk_delay", cfg.Deception.TarpitChunkDelay)
		if err != nil {
			return err
		}
		tarpit := deception.NewTarpit(cfg.Deception.TarpitMaxConns, cfg.Deception.TarpitChunks, chunkDelay)
		originHandler = tarpit.Dispatch(originHandler)
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
	antiBot := antibot.New(antibot.NewRules(*cfg), scoreManager, cfg.RiskEngine.ShadowMode)
	riskMiddleware, err := risk.NewMiddleware(store, scoreManager, *cfg)
	if err != nil {
		return err
	}
	metrics := wafmetrics.New()
	// Détecteurs avancés : publient des contributions de signal consommées par le
	// moteur de risque ; exécutés juste avant lui (Phase 8).
	detectors := []func(http.Handler) http.Handler{
		integrity.NewAnalyzer(*cfg).Handler,
	}
	var adaptiveController *adaptive.Controller
	if cfg.Adaptive.Enabled {
		decayTau, err := parseDuration("adaptive.decay_tau", cfg.Adaptive.DecayTau)
		if err != nil {
			return err
		}
		adaptiveController = adaptive.NewController(cfg.Challenge.PowDifficulty, cfg.Adaptive.MaxDifficulty, decayTau)
		antiDDoS = antiDDoS.WithPressureObserver(func(level antiddos.PressureLevel) {
			adaptiveController.ObservePressure(string(level))
		})
		controller := adaptiveController
		detectors = append(detectors, func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				controller.Observe()
				metrics.SetPowDifficulty(controller.Snapshot())
				next.ServeHTTP(w, r)
			})
		})
	}
	if cfg.Behavioral.Enabled {
		behavioralTracker := behavioral.New(cfg.Behavioral.MaxRecords)
		defer behavioralTracker.Close()
		detectors = append(detectors, behavioralTracker.Handler)
	}
	if cfg.ThreatIntel.Enabled {
		cacheTTL, err := parseDuration("threat_intel.cache_ttl", cfg.ThreatIntel.CacheTTL)
		if err != nil {
			return err
		}
		staticSource := threatintel.NewStaticSource()
		for _, cidr := range cfg.ThreatIntel.BlocklistCIDRs {
			staticSource.Add(cidr, threatintel.LevelMalicious, "blocklist")
		}
		for _, cidr := range cfg.ThreatIntel.SuspectCIDRs {
			staticSource.Add(cidr, threatintel.LevelSuspect, "suspect_range")
		}
		sources := []threatintel.Source{staticSource}
		if cfg.ThreatIntel.AbuseIPDB.Enabled {
			sources = append(sources, threatintel.NewHTTPSource(cfg.ThreatIntel.AbuseIPDB.URL, cfg.ThreatIntel.AbuseIPDB.APIKey, nil))
		}
		threatChecker := threatintel.NewChecker(cacheTTL, sources...)
		detectors = append(detectors, threatintel.NewMiddleware(threatChecker, scoreManager).Handler)
	}
	if cfg.Geo.Enabled {
		detectors = append(detectors, geo.NewRules(cfg.Geo).Handler)
	}
	if cfg.TLSFingerprint.Enabled {
		detectors = append(detectors, tlsfp.NewMiddleware(cfg.TLSFingerprint).Handler)
	}
	if cfg.Rules.Enabled {
		ruleSet := rules.NewRuleSet()
		if err := ruleSet.LoadFile(cfg.Rules.File); err != nil {
			return err
		}
		detectors = append(detectors, rules.NewMiddleware(ruleSet, scoreManager).Handler)
	}
	challengeMiddleware, err := challenge.NewMiddleware(*cfg, scoreManager, "web/challenge.html")
	if err != nil {
		return err
	}
	if adaptiveController != nil {
		challengeMiddleware = challengeMiddleware.WithDifficultyProvider(adaptiveController.Difficulty)
	}
	// Synchronisation multi-nœuds (FR-20) : applique les événements entrants
	// (blacklist, scores critiques) à l'état local. Fallback autonome si Redis
	// est indisponible.
	if cfg.Cluster.Enabled && cfg.Storage.Redis != nil {
		channel := cfg.Cluster.Channel
		if channel == "" {
			channel = "waf:events"
		}
		bus := cluster.NewRedisBus(*cfg.Storage.Redis, channel)
		defer func() { _ = bus.Close() }()
		syncer := cluster.NewSyncer(bus, store, accessRules)
		clusterCtx, clusterCancel := context.WithCancel(context.Background())
		defer clusterCancel()
		if err := bus.Subscribe(clusterCtx, func(event cluster.Event) {
			syncer.Apply(event)
			metrics.IncClusterSync(event.Type)
		}); err != nil {
			return err
		}
	}
	securityLogger := waflogger.New(cfg.Logging)
	defer func() { _ = securityLogger.Close() }()     // vide le writer async à l'arrêt
	securityLogger.AnonymizeIP = cfg.GDPR.AnonymizeIP // RGPD (FR-28)
	// Alerting webhooks (FR-29) : le logger émet une alerte sur les événements
	// à forte sévérité (block / circuit / honeypot), avec cooldown.
	var notifier *alert.Notifier
	if cfg.Alerting.Enabled {
		cooldown, err := parseDuration("alerting.cooldown", cfg.Alerting.Cooldown)
		if err != nil {
			return err
		}
		sinks := make([]alert.Sink, 0, len(cfg.Alerting.Webhooks))
		for _, wh := range cfg.Alerting.Webhooks {
			sinks = append(sinks, alert.Sink{Type: wh.Type, URL: wh.URL})
		}
		notifier = alert.NewNotifier(sinks, cooldown, cfg.Alerting.MaxRetries, nil)
		defer notifier.Close()
		securityLogger.Alerter = notifier
	}
	// Mode sous attaque (FR-39) : à chaque entrée/sortie, on publie la métrique
	// waf_under_attack{domain} et (si l'alerting est actif) on émet une alerte.
	if detector := antiDDoS.UnderAttackDetector(); detector != nil {
		detector.WithTransitionObserver(func(scope string, active bool) {
			metrics.SetUnderAttack(scope, active)
			if notifier == nil {
				return
			}
			trigger := "under_attack_end"
			if active {
				trigger = "under_attack_start"
			}
			// Immediate: une transition est un événement discret (déjà débouncé par
			// l'hystérésis du contrôleur) ; elle ne doit pas être avalée par le
			// cooldown de dédup (sinon une réactivation rapprochée n'alerte pas).
			notifier.Notify(alert.Event{Trigger: trigger, Domain: scope, Immediate: true})
		})
	}

	server := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           routes(*cfg, accessRules, securityLogger, metrics, antiDDoS, rateLimiter, antiBot, riskMiddleware, challengeMiddleware, scoreManager, detectors, originHandler),
		ReadHeaderTimeout: headerTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		// FR-23 : borne le coût de parsing d'une requête portant des milliers de
		// lignes d'en-tête, en amont de tout middleware.
		MaxHeaderValueCount: cfg.Server.MaxHeaderValueCount,
	}
	// ACME / Let's Encrypt (FR-31) : TLS direct avec renouvellement automatique
	// (~30j avant expiration) et rotation à chaud via autocert.
	var acmeManager *acme.Manager
	if cfg.ACME.Enabled {
		acmeManager = acme.NewManager(cfg.ACME)
		server.Addr = cfg.ACME.TLSListen
		server.TLSConfig = acmeManager.TLSConfig()
	}
	// Terminaison TLS par domaine via SNI (FR-33). Mutuellement exclusif avec
	// ACME sur le même listener (garanti par config.Validate). Le chargement des
	// certificats échoue vite (fichier manquant / clé non concordante).
	var tlsManager *tlsmgr.Manager
	if cfg.Server.TLS.Enabled {
		tlsManager, err = tlsmgr.New(*cfg)
		if err != nil {
			return err
		}
		server.Addr = cfg.Server.TLS.Listen
		server.TLSConfig = tlsManager.TLSConfig()
		for domain, notAfter := range tlsManager.Expiries() {
			metrics.SetTLSCertExpiry(domain, notAfter)
		}
	}
	tlsEnabled := acmeManager != nil || tlsManager != nil
	var adminServer *admin.Server
	if cfg.Admin.Enabled {
		adminServer, err = admin.NewServer(*cfg, store, scoreManager, accessRules, startedAt)
		if err != nil {
			return err
		}
	}

	errs := make(chan error, 1)
	go func() {
		slog.Info("starting waf", "listen", server.Addr, "tls", tlsEnabled)
		var serveErr error
		if tlsEnabled {
			serveErr = server.ListenAndServeTLS("", "") // certs fournis par autocert ou tlsmgr (GetCertificate)
		} else {
			serveErr = server.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errs <- serveErr
			return
		}
		errs <- nil
	}()
	// Serveur HTTP-01 (challenge ACME + redirection HTTPS) sur le port 80.
	if acmeManager != nil {
		challengeServer := &http.Server{
			Addr:                cfg.ACME.HTTPChallengeListen,
			Handler:             acmeManager.HTTPHandler(nil),
			ReadHeaderTimeout:   headerTimeout,
			MaxHeaderValueCount: cfg.Server.MaxHeaderValueCount,
		}
		go func() {
			if err := challengeServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}()
		defer func() { _ = challengeServer.Close() }()
	}
	// Redirection HTTP -> HTTPS (FR-33) quand le WAF termine lui-même le TLS par
	// domaine et que redirect_http est actif.
	if tlsManager != nil && cfg.Server.TLS.RedirectHTTP {
		redirectServer := &http.Server{
			Addr:                cfg.Server.Listen,
			Handler:             redirectToHTTPS(cfg.Domains),
			ReadHeaderTimeout:   headerTimeout,
			MaxHeaderValueCount: cfg.Server.MaxHeaderValueCount,
		}
		go func() {
			if err := redirectServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}()
		defer func() { _ = redirectServer.Close() }()
	}
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
	if cfg.OriginProtection.Enabled {
		// Protection de l'origine (FR-19) : endpoint de vérification + injection
		// du token signé vers l'upstream (le proxy transmet le header).
		signer := origin.NewSigner(cfg.OriginProtection.Secret)
		mux.HandleFunc("/waf/origin/verify", signer.VerifyHandler)
		proxyHandler = signer.Injector(proxyHandler)
	}
	if cfg.RiskEngine.Enabled && riskMiddleware != nil {
		proxyHandler = riskMiddleware.Handler(proxyHandler)
	} else {
		proxyHandler = scoreManager.Middleware(proxyHandler)
	}
	// Détecteurs avancés exécutés juste avant le moteur de risque (wrap en ordre
	// inverse pour préserver l'ordre d'exécution detectors[0], detectors[1], ...).
	for _, detector := range slices.Backward(detectors) {
		proxyHandler = detector(proxyHandler)
	}
	proxyHandler = antiBot.Handler(proxyHandler)
	if cfg.RateLimit.Enabled {
		proxyHandler = rateLimiter.Handler(proxyHandler)
	}
	// FR-06 : monté dès qu'au moins un hôte peut être challengé — soit
	// challenge.enabled, soit un domains[].challenge_enabled à true. La décision
	// par requête est prise dans le middleware, qui connaît l'hôte.
	if challenge.Enabled(cfg) {
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
	// Auto-protection (FR-30) : limite le flood de POST /waf/verify par IP.
	if cfg.SelfProtection.Enabled {
		verifyWindow := selfprotect.NewWindow(cfg.SelfProtection.VerifyMaxPerMinute, time.Minute)
		proxyHandler = selfprotect.PathGuard("/waf/verify", verifyWindow)(proxyHandler)
	}
	// Bypass des assets statiques (FR-24) : le plus en amont du pipeline pour
	// marquer PASS avant challenge/trust/détecteurs (la blacklist reste appliquée).
	if cfg.StaticAssets.Enabled {
		proxyHandler = staticassets.New(cfg.StaticAssets).Handler(proxyHandler)
	}
	mux.Handle("/", proxyHandler)
	var handler http.Handler = mux
	// Protection Slowloris (FR-23) : limite les requêtes concurrentes par IP.
	if cfg.Slowloris.Enabled {
		handler = slowloris.New(cfg.Slowloris.MaxConnsPerIP).Handler(handler)
	}
	// Mode maintenance + pages d'erreur brandées (FR-32).
	handler = maintenance.New(cfg.Maintenance).Handler(handler)
	// En-têtes de sécurité + sanitisation (FR-21/FR-22) : le plus à l'extérieur.
	if cfg.SecurityHeaders.Enabled {
		handler = secheaders.New(cfg.SecurityHeaders).Handler(handler)
	}
	return handler
}

// redirectToHTTPS renvoie un handler de redirection HTTP→HTTPS qui valide le
// Host entrant contre les domaines configurés avant de rediriger. Un Host non
// reconnu reçoit un 400 : sans cette garde, un attaquant peut injecter un Host
// arbitraire et forcer une redirection vers un domaine tiers (open-redirect).
func redirectToHTTPS(domains []config.DomainConfig) http.HandlerFunc {
	allowed := make([]string, len(domains))
	for i, d := range domains {
		allowed[i] = d.Host
	}
	return func(w http.ResponseWriter, r *http.Request) {
		host := stripPort(r.Host)
		if !hostAllowed(host, allowed) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		// Construire l'URL via url.URL plutôt que par concaténation de strings
		// pour éviter l'open-redirect par chemin commençant par "//evil.com"
		// (ex: r.URL.Path = "//evil.com/x" → navigateur interprète comme host).
		target := &url.URL{
			Scheme:   "https",
			Host:     host,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
		}
		http.Redirect(w, r, target.String(), http.StatusMovedPermanently) //nolint // nosemgrep: go.lang.security.injection.open-redirect.open-redirect
	}
}

// hostAllowed vérifie qu'un host correspond à l'un des patterns configurés
// (exact ou wildcard de la forme "*.example.com").
func hostAllowed(host string, patterns []string) bool {
	for _, p := range patterns {
		if strings.HasPrefix(p, "*.") {
			if strings.HasSuffix(host, p[1:]) { // p[1:] == ".example.com"
				return true
			}
		} else if host == p {
			return true
		}
	}
	return false
}

func stripPort(hostport string) string {
	if before, _, ok := strings.Cut(hostport, ":"); ok {
		return before
	}
	return hostport
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
