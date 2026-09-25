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
	"slices"
	"sync"
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
	wafmetrics "github.com/gaetandev/waf/internal/metrics"
	"github.com/gaetandev/waf/internal/middleware/access"
	"github.com/gaetandev/waf/internal/middleware/antibot"
	"github.com/gaetandev/waf/internal/middleware/antiddos"
	"github.com/gaetandev/waf/internal/middleware/challenge"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/middleware/ratelimit"
	"github.com/gaetandev/waf/internal/proxy"
	"github.com/gaetandev/waf/internal/risk"
	"github.com/gaetandev/waf/internal/rules"
	"github.com/gaetandev/waf/internal/storage"
	"github.com/gaetandev/waf/internal/storage/memory"
	redisstore "github.com/gaetandev/waf/internal/storage/redis"
	"github.com/gaetandev/waf/internal/threatintel"
	"github.com/gaetandev/waf/internal/tlsfp"
	"github.com/gaetandev/waf/internal/tlsmgr"
	"github.com/gaetandev/waf/internal/trust"
	"github.com/gaetandev/waf/internal/upstream"
	"github.com/gaetandev/waf/web"
)

// defaultHeaderTimeout borne la lecture des en-têtes quand slowloris est
// désactivé.
const defaultHeaderTimeout = 10 * time.Second

// maxListeners est le nombre maximal de serveurs HTTP démarrés par run :
// public, challenge ACME HTTP-01, redirection HTTP→HTTPS et API admin.
const maxListeners = 4

type cliFlags struct {
	configPath     string
	listenAddress  string
	healthCheck    bool
	healthCheckURL string
}

func parseFlags() cliFlags {
	var flags cliFlags
	flag.StringVar(&flags.configPath, "config", defaultConfigPath, "config YAML path")
	flag.StringVar(&flags.listenAddress, "listen", "", "override public HTTP listen address")
	flag.BoolVar(&flags.healthCheck, "healthcheck", false, "probe the health endpoint and exit (for container HEALTHCHECK)")
	flag.StringVar(&flags.healthCheckURL, "health-url", defaultHealthCheckURL, "health endpoint URL probed by -healthcheck")
	flag.Parse()
	return flags
}

// loadConfig charge la configuration, applique les surcharges de la ligne de
// commande et signale les réglages rendus inertes.
func loadConfig(flags cliFlags) (*config.Config, error) {
	cfg, err := config.Load(flags.configPath)
	if err != nil {
		return nil, err
	}
	if flags.listenAddress != "" {
		cfg.Server.Listen = flags.listenAddress
	}
	warnUntrustedInfrastructureHeaders(*cfg)
	if geoChallengeInert(*cfg) {
		slog.Warn("geo.challenge_countries has no effect while risk_engine.enabled is false: only the risk engine reads the geo contribution", "requirement", "FR-16")
	}
	for _, host := range poolShadowedDomains(*cfg) {
		slog.Warn("domains[].upstream is ignored while upstream_pool is enabled: the pool serves every host", "host", host, "requirement", "FR-26")
	}
	return cfg, nil
}

type serverTimeouts struct {
	read, write, idle, shutdown, header time.Duration
}

func parseServerTimeouts(cfg config.Config) (serverTimeouts, error) {
	var (
		timeouts serverTimeouts
		err      error
	)
	fields := []struct {
		name  string
		value string
		out   *time.Duration
	}{
		{"server.read_timeout", cfg.Server.ReadTimeout, &timeouts.read},
		{"server.write_timeout", cfg.Server.WriteTimeout, &timeouts.write},
		{"server.idle_timeout", cfg.Server.IdleTimeout, &timeouts.idle},
		{"server.graceful_shutdown_timeout", cfg.Server.GracefulShutdownTimeout, &timeouts.shutdown},
	}
	for _, field := range fields {
		if *field.out, err = parseDuration(field.name, field.value); err != nil {
			return timeouts, err
		}
	}
	timeouts.header = defaultHeaderTimeout
	if cfg.Slowloris.Enabled {
		if timeouts.header, err = parseDuration("slowloris.header_timeout", cfg.Slowloris.HeaderTimeout); err != nil {
			return timeouts, err
		}
	}
	return timeouts, nil
}

// cleanup empile les arrêts des composants construits par run. Ils s'exécutent
// en ordre inverse d'empilement, comme les defer qu'ils remplacent.
type cleanup []func()

func (c *cleanup) add(stop func()) {
	*c = append(*c, stop)
}

func (c cleanup) run() {
	for _, stop := range slices.Backward(c) {
		stop()
	}
}

// app regroupe les composants que run construit puis câble. Chaque étape de
// build en remplit une partie, dans l'ordre de dépendance ; stop empile leurs
// arrêts.
type app struct {
	cfg       *config.Config
	startedAt time.Time
	stop      cleanup

	origin              http.Handler
	accessRules         *access.RuleSet
	metrics             *wafmetrics.Metrics
	store               storage.Store
	scoreManager        *trust.ScoreManager
	antiDDoS            antiddos.Middleware
	rateLimiter         *ratelimit.Middleware
	antiBot             antibot.Middleware
	riskMiddleware      *risk.Middleware
	detectors           []func(http.Handler) http.Handler
	adaptiveController  *adaptive.Controller
	challengeMiddleware challenge.Middleware
	syncer              *cluster.Syncer
	securityLogger      waflogger.Logger
	notifier            *alert.Notifier
	adminServer         *admin.Server
}

func (a *app) build() error {
	steps := []func() error{
		a.buildOrigin,
		a.buildState,
		a.buildProtection,
		a.buildDetectors,
		a.buildChallenge,
		a.buildCluster,
		a.buildLogging,
		a.buildAdmin,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

// buildOrigin construit la cible finale du pipeline : le proxy, éventuellement
// sur un pool d'upstreams, précédé du tarpit (déception, FR-15) qui intercepte
// les requêtes classées TARPIT par le moteur de risque avant l'origine.
func (a *app) buildOrigin() error {
	proxyHandler, err := proxy.NewHandler(*a.cfg)
	if err != nil {
		return err
	}
	if a.cfg.UpstreamPool.Enabled {
		if err := a.attachUpstreamPool(proxyHandler); err != nil {
			return err
		}
	}
	a.origin = proxyHandler
	if a.cfg.Deception.Enabled {
		chunkDelay, err := parseDuration("deception.tarpit_chunk_delay", a.cfg.Deception.TarpitChunkDelay)
		if err != nil {
			return err
		}
		tarpit := deception.NewTarpit(a.cfg.Deception.TarpitMaxConns, a.cfg.Deception.TarpitChunks, chunkDelay)
		a.origin = tarpit.Dispatch(a.origin)
	}
	return nil
}

// attachUpstreamPool branche le pool d'upstreams, ses health checks et son
// load balancing (FR-25/26) sur le proxy.
func (a *app) attachUpstreamPool(proxyHandler *proxy.Handler) error {
	cfg := a.cfg
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
	a.stop.add(hcCancel)
	checker.Start(hcCtx)
	return nil
}

// buildState construit les listes d'accès, les métriques et le stockage.
func (a *app) buildState() error {
	accessRules, err := access.NewRuleSet(a.cfg.Whitelist, a.cfg.Blacklist, a.cfg.WhitelistUserAgents)
	if err != nil {
		return err
	}
	a.accessRules = accessRules
	a.metrics = wafmetrics.New().WithDomains(domainHosts(a.cfg.Domains))
	store, err := newStore(*a.cfg, a.metrics)
	if err != nil {
		return err
	}
	a.store = store
	a.stop.add(store.Close)
	if a.cfg.Cloudflare.Trusted && a.cfg.Cloudflare.AutoUpdateRanges {
		return a.startCloudflareRangeUpdater()
	}
	return nil
}

// startCloudflareRangeUpdater rafraîchit les plages IP Cloudflare (FR-02).
// Tâche de fond : le WAF sert immédiatement avec la liste compilée, et un échec
// de récupération laisse la liste en vigueur intacte plutôt que d'empêcher le
// démarrage.
func (a *app) startCloudflareRangeUpdater() error {
	rangeInterval, err := parseDuration("cloudflare.update_interval", a.cfg.Cloudflare.UpdateInterval)
	if err != nil {
		return err
	}
	metrics := a.metrics
	updater := cloudflare.NewUpdater(rangeInterval, cloudflare.WithObservers(
		func(count int) {
			metrics.SetCloudflareRanges(count)
			metrics.IncCloudflareRangeUpdate("success")
			slog.Info("cloudflare ip ranges refreshed", "prefixes", count)
		},
		func(err error) {
			metrics.IncCloudflareRangeUpdate("error")
			// Warn et non Error : la liste précédente reste en vigueur, le WAF
			// continue de valider CF-Connecting-IP correctement.
			slog.Warn("cloudflare ip ranges refresh failed", "error", err)
		},
	))
	rangeCtx, rangeCancel := context.WithCancel(context.Background())
	a.stop.add(rangeCancel)
	updater.Start(rangeCtx)
	return nil
}

// buildProtection construit le trust score et les middlewares de protection
// de la chaîne publique.
func (a *app) buildProtection() error {
	cfg := *a.cfg
	scoreManager, err := trust.NewScoreManager(a.store, cfg)
	if err != nil {
		return err
	}
	a.scoreManager = scoreManager
	a.metrics.WithVisitorBounds(scoreManager.TTL(), cfg.Trust.MaxVisitors)
	if a.antiDDoS, err = antiddos.NewFromConfig(a.store, cfg); err != nil {
		return err
	}
	if a.rateLimiter, err = ratelimit.New(a.store, scoreManager, cfg); err != nil {
		return err
	}
	a.antiBot = antibot.New(antibot.NewRules(cfg), scoreManager, cfg.RiskEngine.ShadowMode)
	if a.riskMiddleware, err = risk.NewMiddleware(a.store, scoreManager, cfg); err != nil {
		return err
	}
	a.riskMiddleware.WithThrottle(a.rateLimiter.Throttle)
	a.stop.add(a.riskMiddleware.Close)
	return nil
}

// buildDetectors construit les détecteurs avancés : ils publient des
// contributions de signal consommées par le moteur de risque, et s'exécutent
// juste avant lui (Phase 8).
func (a *app) buildDetectors() error {
	cfg := a.cfg
	a.detectors = []func(http.Handler) http.Handler{
		integrity.NewAnalyzer(*cfg).Handler,
	}
	if cfg.Adaptive.Enabled {
		if err := a.addAdaptiveDetector(); err != nil {
			return err
		}
	}
	if cfg.Behavioral.Enabled {
		behavioralTracker := behavioral.New(cfg.Behavioral.MaxRecords, cfg.Trust.MaxVisitors)
		a.stop.add(behavioralTracker.Close)
		a.detectors = append(a.detectors, behavioralTracker.Handler)
	}
	if cfg.ThreatIntel.Enabled {
		if err := a.addThreatIntelDetector(); err != nil {
			return err
		}
	}
	if cfg.Geo.Enabled {
		a.detectors = append(a.detectors, geo.NewRules(cfg.Geo).Handler)
	}
	if cfg.TLSFingerprint.Enabled {
		a.detectors = append(a.detectors, tlsfp.NewMiddleware(cfg.TLSFingerprint, cfg.Trust.MaxVisitors).Handler)
	}
	if cfg.Rules.Enabled {
		ruleSet := rules.NewRuleSet()
		if err := ruleSet.LoadFile(cfg.Rules.File); err != nil {
			return err
		}
		a.detectors = append(a.detectors, rules.NewMiddleware(ruleSet, a.scoreManager).Handler)
	}
	return nil
}

// addAdaptiveDetector branche la difficulté adaptative du PoW (FR-14) : elle
// suit le débit observé et la pression anti-DDoS.
func (a *app) addAdaptiveDetector() error {
	decayTau, err := parseDuration("adaptive.decay_tau", a.cfg.Adaptive.DecayTau)
	if err != nil {
		return err
	}
	controller := adaptive.NewController(a.cfg.Challenge.PowDifficulty, a.cfg.Adaptive.MaxDifficulty, decayTau)
	a.adaptiveController = controller
	a.antiDDoS = a.antiDDoS.WithPressureObserver(func(level antiddos.PressureLevel) {
		controller.ObservePressure(string(level))
	})
	metrics := a.metrics
	a.detectors = append(a.detectors, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			metrics.SetPowDifficulty(controller.Observe())
			next.ServeHTTP(w, r)
		})
	})
	return nil
}

// addThreatIntelDetector branche la réputation IP (FR-13) : feeds CIDR
// locaux et, en option, AbuseIPDB.
func (a *app) addThreatIntelDetector() error {
	cfg := a.cfg.ThreatIntel
	cacheTTL, err := parseDuration("threat_intel.cache_ttl", cfg.CacheTTL)
	if err != nil {
		return err
	}
	staticSource := threatintel.NewStaticSource()
	for _, cidr := range cfg.BlocklistCIDRs {
		staticSource.Add(cidr, threatintel.LevelMalicious, "blocklist")
	}
	for _, cidr := range cfg.SuspectCIDRs {
		staticSource.Add(cidr, threatintel.LevelSuspect, "suspect_range")
	}
	sources := []threatintel.Source{staticSource}
	if cfg.AbuseIPDB.Enabled {
		sources = append(sources, threatintel.NewHTTPSource(cfg.AbuseIPDB.URL, cfg.AbuseIPDB.APIKey, nil))
	}
	threatChecker := threatintel.NewChecker(cacheTTL, sources...)
	a.stop.add(threatChecker.Close)
	a.detectors = append(a.detectors, threatintel.NewMiddleware(threatChecker, a.scoreManager).Handler)
	return nil
}

func (a *app) buildChallenge() error {
	// Page embarquée : le binaire démarre hors de la racine du dépôt (G7).
	challengeMiddleware, err := challenge.NewMiddlewareFromSource(*a.cfg, a.scoreManager, web.ChallengePage)
	if err != nil {
		return err
	}
	if a.adaptiveController != nil {
		challengeMiddleware = challengeMiddleware.WithDifficultyProvider(a.adaptiveController.Difficulty)
	}
	if a.cfg.RiskEngine.Enabled {
		challengeMiddleware = challengeMiddleware.WithHumanCredit(a.riskMiddleware.GrantChallengePass)
	}
	a.challengeMiddleware = challengeMiddleware
	return nil
}

// buildCluster branche la synchronisation multi-nœuds (FR-20) : publie les
// décisions locales (blacklist admin, ouverture de circuit, score critique) et
// applique celles des autres nœuds. Fallback autonome si Redis est
// indisponible.
func (a *app) buildCluster() error {
	cfg := a.cfg
	if !cfg.Cluster.Enabled || cfg.Storage.Redis == nil {
		return nil
	}
	channel := cfg.Cluster.Channel
	if channel == "" {
		channel = "waf:events"
	}
	bus := cluster.NewRedisBus(*cfg.Storage.Redis, channel)
	a.stop.add(func() { _ = bus.Close() })
	syncer := cluster.NewSyncer(bus, a.store, a.accessRules)
	clusterCtx, clusterCancel := context.WithCancel(context.Background())
	a.stop.add(clusterCancel)
	metrics := a.metrics
	if err := bus.Subscribe(clusterCtx, func(event cluster.Event) {
		if syncer.Apply(event) {
			metrics.IncClusterSync(event.Type)
		}
	}); err != nil {
		return err
	}
	go syncer.RunPublisher(clusterCtx)
	a.antiDDoS = a.antiDDoS.WithCircuitOpenObserver(syncer.PublishCircuitOpen)
	a.scoreManager.WithCriticalObserver(syncer.PublishScoreCritical)
	a.syncer = syncer
	return nil
}

// buildLogging construit le journal de sécurité et, si actif, l'alerting.
func (a *app) buildLogging() error {
	a.securityLogger = waflogger.New(a.cfg.Logging)
	a.stop.add(func() { _ = a.securityLogger.Close() })   // vide le writer async à l'arrêt
	a.securityLogger.AnonymizeIP = a.cfg.GDPR.AnonymizeIP // RGPD (FR-28)
	if a.cfg.Alerting.Enabled {
		if err := a.buildAlerting(); err != nil {
			return err
		}
	}
	a.observeUnderAttack()
	return nil
}

// buildAlerting branche les webhooks (FR-29) : le logger émet une alerte sur
// les événements à forte sévérité (block / circuit / honeypot), avec cooldown.
func (a *app) buildAlerting() error {
	cfg := a.cfg.Alerting
	cooldown, err := parseDuration("alerting.cooldown", cfg.Cooldown)
	if err != nil {
		return err
	}
	sinks := make([]alert.Sink, 0, len(cfg.Webhooks))
	for _, wh := range cfg.Webhooks {
		sinks = append(sinks, alert.Sink{Type: wh.Type, URL: wh.URL})
	}
	notifier := alert.NewNotifier(sinks, cooldown, cfg.MaxRetries, nil, alert.WithObserver(a.metrics))
	a.stop.add(notifier.Close)
	a.metrics.WithAlertsPending(notifier.Pending)
	a.securityLogger.Alerter = notifier
	a.notifier = notifier
	return nil
}

// observeUnderAttack publie, à chaque entrée/sortie du mode sous attaque
// (FR-39), la métrique waf_under_attack{domain} et (si l'alerting est actif)
// une alerte.
func (a *app) observeUnderAttack() {
	detector := a.antiDDoS.UnderAttackDetector()
	if detector == nil {
		return
	}
	metrics, notifier := a.metrics, a.notifier
	detector.WithTransitionObserver(func(scope string, active bool) {
		metrics.SetUnderAttack(scope, active)
		if notifier == nil {
			return
		}
		trigger := alert.TriggerUnderAttackEnd
		if active {
			trigger = alert.TriggerUnderAttackStart
		}
		// Immediate: une transition est un événement discret (déjà débouncé par
		// l'hystérésis du contrôleur) ; elle ne doit pas être avalée par le
		// cooldown de dédup (sinon une réactivation rapprochée n'alerte pas).
		notifier.Notify(alert.Event{Trigger: trigger, Domain: scope, Immediate: true})
	})
}

// buildAdmin construit l'API admin avant la chaîne publique : son flux
// d'événements (GET /waf/admin/events) est alimenté par le logger.
func (a *app) buildAdmin() error {
	if !a.cfg.Admin.Enabled {
		return nil
	}
	adminServer, err := admin.NewServer(*a.cfg, a.store, a.scoreManager, a.accessRules, a.startedAt)
	if err != nil {
		return err
	}
	a.securityLogger.Recorder = adminServer.EventRecorder()
	if a.syncer != nil {
		adminServer.WithBlacklistObserver(a.syncer.PublishBlacklistAdd)
		a.syncer.WithBlacklistApplier(adminServer.ApplyClusterBlacklist)
	}
	// PATCH /waf/admin/config (hot-reload) : la configuration validée est
	// poussée aux composants qui la lisent par requête.
	rateLimiter, scoreManager, challengeMiddleware, adaptiveController := a.rateLimiter, a.scoreManager, a.challengeMiddleware, a.adaptiveController
	adminServer.WithConfigApplier(func(next config.Config) {
		rateLimiter.Configure(next.RateLimit)
		scoreManager.SetThresholds(next.Trust.ChallengeThreshold, next.Trust.BlockThreshold)
		challengeMiddleware.Configure(next.Challenge)
		if adaptiveController != nil {
			adaptiveController.SetBaseDifficulty(next.Challenge.PowDifficulty)
		}
		slog.Info("runtime configuration updated")
	})
	a.adminServer = adminServer
	return nil
}

// serve démarre les serveurs HTTP et les arrête proprement sur SIGINT/SIGTERM.
func (a *app) serve(timeouts serverTimeouts) error {
	cfg := a.cfg
	server := &http.Server{
		Addr:              cfg.Server.Listen,
		Handler:           a.routes(),
		ReadHeaderTimeout: timeouts.header,
		ReadTimeout:       timeouts.read,
		WriteTimeout:      timeouts.write,
		IdleTimeout:       timeouts.idle,
		// FR-23 : borne le coût de parsing d'une requête portant des milliers de
		// lignes d'en-tête, en amont de tout middleware.
		MaxHeaderValueCount: cfg.Server.MaxHeaderValueCount,
	}
	acmeManager, tlsManager, err := a.configureTLS(server)
	if err != nil {
		return err
	}
	tlsEnabled := acmeManager != nil || tlsManager != nil

	// Un emplacement par serveur : avec un canal de capacité 1, une deuxième
	// erreur (ex. ports 443 et 80 déjà pris) bloquait sa goroutine pour toujours.
	errs := make(chan error, maxListeners)
	servers := []namedServer{{name: "public", server: server}}
	slog.Info("starting waf", "listen", server.Addr, "tls", tlsEnabled)
	if tlsEnabled {
		listenInBackground(errs, func() error { return server.ListenAndServeTLS("", "") }) // certs fournis par autocert ou tlsmgr (GetCertificate)
	} else {
		listenInBackground(errs, server.ListenAndServe)
	}
	// Serveur HTTP-01 (challenge ACME + redirection HTTPS) sur le port 80.
	if acmeManager != nil {
		challengeServer := a.newSideServer(cfg.ACME.HTTPChallengeListen, acmeManager.HTTPHandler(nil), timeouts.header)
		listenInBackground(errs, challengeServer.ListenAndServe)
		servers = append(servers, namedServer{name: "acme challenge", server: challengeServer})
	}
	// Redirection HTTP -> HTTPS (FR-40) quand le WAF termine lui-même le TLS par
	// domaine et que redirect_http est actif.
	if tlsManager != nil && cfg.Server.TLS.RedirectHTTP {
		redirectServer := a.newSideServer(cfg.Server.Listen, redirectToHTTPS(cfg.Domains), timeouts.header)
		listenInBackground(errs, redirectServer.ListenAndServe)
		servers = append(servers, namedServer{name: "https redirect", server: redirectServer})
	}
	if a.adminServer != nil {
		slog.Info("starting admin api", "listen", cfg.Server.AdminListen)
		listenInBackground(errs, a.adminServer.ListenAndServe)
		servers = append(servers, namedServer{name: "admin", server: a.adminServer})
	}
	return awaitShutdown(servers, errs, timeouts.shutdown)
}

// gracefulServer est satisfait par *http.Server et par l'API admin.
type gracefulServer interface {
	Shutdown(ctx context.Context) error
}

// namedServer nomme un serveur démarré, pour situer un échec d'arrêt.
type namedServer struct {
	name   string
	server gracefulServer
}

// configureTLS attache au serveur public ACME / Let's Encrypt (FR-31) ou la
// terminaison TLS par domaine via SNI (FR-40), mutuellement exclusifs sur le
// même listener (garanti par config.Validate).
func (a *app) configureTLS(server *http.Server) (*acme.Manager, *tlsmgr.Manager, error) {
	// ACME : TLS direct avec renouvellement automatique (~30j avant
	// expiration) et rotation à chaud via autocert.
	var acmeManager *acme.Manager
	if a.cfg.ACME.Enabled {
		acmeManager = acme.NewManager(a.cfg.ACME)
		server.Addr = a.cfg.ACME.TLSListen
		server.TLSConfig = acmeManager.TLSConfig()
	}
	// Le chargement des certificats par domaine échoue vite (fichier manquant
	// / clé non concordante).
	var tlsManager *tlsmgr.Manager
	if a.cfg.Server.TLS.Enabled {
		manager, err := tlsmgr.New(*a.cfg)
		if err != nil {
			return nil, nil, err
		}
		tlsManager = manager
		server.Addr = a.cfg.Server.TLS.Listen
		server.TLSConfig = tlsManager.TLSConfig()
		for domain, notAfter := range tlsManager.Expiries() {
			a.metrics.SetTLSCertExpiry(domain, notAfter)
		}
	}
	return acmeManager, tlsManager, nil
}

// newSideServer construit un serveur annexe (challenge ACME HTTP-01,
// redirection HTTPS), hors de la chaîne de protection.
func (a *app) newSideServer(addr string, handler http.Handler, headerTimeout time.Duration) *http.Server {
	return &http.Server{
		Addr:                addr,
		Handler:             handler,
		ReadHeaderTimeout:   headerTimeout,
		MaxHeaderValueCount: a.cfg.Server.MaxHeaderValueCount,
	}
}

// awaitShutdown attend un signal d'arrêt ou l'échec d'un serveur, puis arrête
// tous les serveurs démarrés. L'échec d'un listener arrêtait le processus sans
// arrêter les autres : leurs requêtes en cours touchaient ensuite des stores
// déjà fermés par app.stop.
func awaitShutdown(servers []namedServer, errs chan error, shutdownTimeout time.Duration) error {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)

	var listenErr error
	select {
	case signalReceived := <-stop:
		slog.Info("shutdown requested", "signal", signalReceived.String())
	case listenErr = <-errs:
		slog.Error("server failed, shutting down", "error", listenErr)
	}

	shutdownErr := shutdownAll(servers, shutdownTimeout)
	if listenErr != nil {
		return errors.Join(listenErr, shutdownErr)
	}
	if shutdownErr != nil {
		return shutdownErr
	}
	return drainedError(errs)
}

// shutdownAll arrête les serveurs en parallèle, chacun disposant du délai de
// grâce entier. Arrêtés l'un après l'autre sous un contexte commun, le serveur
// public pouvait consommer tout le délai à drainer ses connexions : l'API admin
// recevait un contexte déjà expiré, et les serveurs annexes n'étaient que
// fermés (Close), sans drainage.
func shutdownAll(servers []namedServer, shutdownTimeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	failures := make([]error, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		wg.Go(func() {
			if err := s.server.Shutdown(ctx); err != nil {
				failures[i] = fmt.Errorf("shutdown %s server: %w", s.name, err)
			}
		})
	}
	wg.Wait()
	return errors.Join(failures...)
}

// listenInBackground lance listen dans une goroutine et remonte son erreur sur
// errs. http.ErrServerClosed, qui signale un arrêt demandé, n'en est pas une :
// l'API admin la remontait, et un arrêt normal pouvait sortir en erreur.
func listenInBackground(errs chan<- error, listen func() error) {
	go func() {
		if err := listen(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()
}

// drainedError retourne une erreur de serveur déjà remontée, sans attendre.
func drainedError(errs <-chan error) error {
	select {
	case err := <-errs:
		return err
	default:
		return nil
	}
}

// newStore construit le backend de stockage désigné par `storage.backend`.
//
// Cette sélection n'existait pas avant la phase 15 : `redis` était accepté par
// la validation de configuration puis ignoré — le WAF servait un état par nœud
// alors que la configuration promettait un état partagé entre instances
// (ADR-002, sémantique d'exécution dans ADR-021).
func newStore(cfg config.Config, observer redisstore.Observer) (storage.Store, error) {
	if cfg.Storage.Backend != storageBackendRedis {
		return memory.New(cfg.Trust.MaxVisitors), nil
	}
	if cfg.Storage.Redis == nil {
		// Déjà refusé par config.Validate ; la garde évite qu'un appel direct
		// déréférence un pointeur nul.
		return nil, errors.New("storage.backend is redis but storage.redis is missing")
	}
	slog.Info("using redis storage backend", "address", cfg.Storage.Redis.Address)
	return redisstore.New(*cfg.Storage.Redis, cfg.Trust.MaxVisitors, redisstore.WithObserver(observer))
}
