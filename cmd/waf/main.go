package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/hostname"
	waflogger "github.com/gaetandev/waf/internal/logger"
	"github.com/gaetandev/waf/internal/maintenance"
	wafmetrics "github.com/gaetandev/waf/internal/metrics"
	"github.com/gaetandev/waf/internal/middleware/access"
	"github.com/gaetandev/waf/internal/middleware/antibot"
	"github.com/gaetandev/waf/internal/middleware/antiddos"
	"github.com/gaetandev/waf/internal/middleware/challenge"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/middleware/ingress"
	"github.com/gaetandev/waf/internal/middleware/ratelimit"
	"github.com/gaetandev/waf/internal/origin"
	"github.com/gaetandev/waf/internal/proxy"
	"github.com/gaetandev/waf/internal/risk"
	"github.com/gaetandev/waf/internal/secheaders"
	"github.com/gaetandev/waf/internal/selfprotect"
	"github.com/gaetandev/waf/internal/slowloris"
	"github.com/gaetandev/waf/internal/staticassets"
	"github.com/gaetandev/waf/internal/storage"
	"github.com/gaetandev/waf/internal/storage/memory"
	redisstore "github.com/gaetandev/waf/internal/storage/redis"
	"github.com/gaetandev/waf/internal/trust"
)

const (
	defaultConfigPath     = "configs/config.example.yaml"
	defaultHealthCheckURL = "http://127.0.0.1:8080/waf/health"

	storageBackendRedis = "redis"
)

func main() {
	if err := run(); err != nil {
		slog.Error("waf stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	startedAt := time.Now()
	flags := parseFlags()
	if flags.healthCheck {
		return runHealthCheck(flags.healthCheckURL)
	}
	cfg, err := loadConfig(flags)
	if err != nil {
		return err
	}
	timeouts, err := parseServerTimeouts(*cfg)
	if err != nil {
		return err
	}

	a := &app{cfg: cfg, startedAt: startedAt}
	defer a.stop.run()
	if err := a.build(); err != nil {
		return err
	}
	return a.serve(timeouts)
}

// warnUntrustedInfrastructureHeaders signale les contrôles privés d'entrée par
// la suppression des CF-* quand cloudflare.trusted est faux (ADR-019 option B).
// Un avertissement et non une erreur : ces réglages restaient valides avant la
// décision, et un déploiement peut les laisser en place le temps de basculer.
func warnUntrustedInfrastructureHeaders(cfg config.Config) {
	if cfg.Cloudflare.Trusted {
		return
	}
	if cfg.Geo.Enabled {
		slog.Warn("geo rules have no input: CF-IPCountry is stripped while cloudflare.trusted is false", "adr", "ADR-019")
	}
	if cfg.TLSFingerprint.Enabled && strings.HasPrefix(strings.ToUpper(cfg.TLSFingerprint.JA3Header), "CF-") {
		slog.Warn("tls_fingerprint.ja3_header is stripped while cloudflare.trusted is false", "header", cfg.TLSFingerprint.JA3Header, "adr", "ADR-019")
	}
}

// poolShadowedDomains retourne les hôtes dont domains[].upstream diffère de
// upstream.address alors que upstream_pool est actif. Le pool, global, sert
// alors tous les hôtes (FR-26 ; pool par domaine différé) : ces upstreams ne
// reçoivent aucune requête. Un avertissement et non une erreur — la clé est
// obligatoire dans domains[], et la configuration reste celle que FR-26 décrit.
func poolShadowedDomains(cfg config.Config) []string {
	if !cfg.UpstreamPool.Enabled {
		return nil
	}
	var hosts []string
	for _, domain := range cfg.Domains {
		if domain.Upstream != cfg.Upstream.Address {
			hosts = append(hosts, domain.Host)
		}
	}
	return hosts
}

// domainHosts retourne les hôtes déclarés dans domains[].
func domainHosts(domains []config.DomainConfig) []string {
	hosts := make([]string, 0, len(domains))
	for _, domain := range domains {
		hosts = append(hosts, domain.Host)
	}
	return hosts
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

func routes(cfg config.Config, accessRules *access.RuleSet, securityLogger waflogger.Logger, metrics *wafmetrics.Metrics, antiDDoS antiddos.Middleware, rateLimiter *ratelimit.Middleware, antiBot antibot.Middleware, riskMiddleware *risk.Middleware, challengeMiddleware challenge.Middleware, scoreManager *trust.ScoreManager, detectors []func(http.Handler) http.Handler, proxyHandler http.Handler) http.Handler {
	guard := envelopeGuard(cfg)
	mux := http.NewServeMux()
	mux.Handle("/waf/health", allowGet(http.HandlerFunc(healthHandler)))
	mux.Handle("/waf/metrics", guard(allowGet(metrics.Handler())))
	if cfg.OriginProtection.Enabled {
		// Protection de l'origine (FR-19) : endpoint de vérification + injection
		// du token signé vers l'upstream (le proxy transmet le header).
		signer := origin.NewSigner(cfg.OriginProtection.Secret)
		mux.Handle("/waf/origin/verify", guard(allowGet(http.HandlerFunc(signer.VerifyHandler))))
		proxyHandler = signer.Injector(proxyHandler)
	}
	// FR-34 / FR-04 : une décision CHALLENGE du moteur de risque ou du trust score
	// sert la page de challenge. Monté en aval de ces décisions, donc ici.
	proxyHandler = challengeMiddleware.Enforcer(proxyHandler)
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
	// Rate limit et challenge sont montés en permanence : rate_limit.enabled et
	// challenge.enabled sont modifiables à chaud (PATCH /waf/admin/config), et
	// chaque middleware lit son réglage courant par requête. La décision de
	// challenge par hôte (FR-06) est prise dans le middleware.
	proxyHandler = rateLimiter.Handler(proxyHandler)
	proxyHandler = challengeMiddleware.Handler(proxyHandler)
	proxyHandler = antiDDoS.Handler(proxyHandler)
	proxyHandler = access.Middleware(accessRules, proxyHandler)
	// Auto-protection (FR-30) : limite le flood de POST /waf/verify par IP.
	if cfg.SelfProtection.Enabled {
		verifyWindow := selfprotect.NewWindow(cfg.SelfProtection.VerifyMaxPerMinute, time.Minute)
		proxyHandler = selfprotect.PathGuard("/waf/verify", verifyWindow)(proxyHandler)
	}
	// Refus d'enveloppe (slowloris, strict_host) et auto-protection sous le
	// journal et les métriques : montés au-dessus, leurs 429 et 400 n'étaient
	// ni comptés dans Prometheus, ni journalisés, ni publiés sur le flux admin.
	proxyHandler = guard(proxyHandler)
	proxyHandler = securityLogger.Middleware(scoreManager, proxyHandler)
	proxyHandler = metrics.Middleware(scoreManager, proxyHandler)
	// Bypass des assets statiques (FR-24) : le plus en amont du pipeline pour
	// marquer PASS avant challenge/trust/détecteurs (la blacklist reste appliquée).
	if cfg.StaticAssets.Enabled {
		proxyHandler = staticassets.New(cfg.StaticAssets).Handler(proxyHandler)
	}
	mux.Handle("/", proxyHandler)
	var handler http.Handler = mux
	// Extraction de l'IP réelle (FR-02) : en amont de tout ce qui compte par IP.
	// Montée plus bas (autour du seul pipeline de proxy), elle laissait slowloris,
	// l'auto-protection de /waf/verify et le bypass d'assets lire RemoteAddr,
	// c'est-à-dire l'IP du point de présence Cloudflare : quelques visiteurs
	// légitimes derrière le même PoP suffisaient à épuiser la borne par IP.
	// Les autres CF-* ne sont honorés que venant d'une plage Cloudflare, et
	// jamais sans cloudflare.trusted (ADR-019 option B).
	if cfg.Cloudflare.Trusted {
		handler = cloudflare.Middleware(handler)
	} else {
		handler = cloudflare.StripUntrusted(handler)
	}
	// Mode maintenance + pages d'erreur brandées (FR-32).
	handler = maintenance.New(cfg.Maintenance).Handler(handler)
	// En-têtes de sécurité + sanitisation (FR-21/FR-22) : le plus à l'extérieur.
	if cfg.SecurityHeaders.Enabled {
		handler = secheaders.New(cfg.SecurityHeaders).Handler(handler)
	}
	// Assainissement de l'ingress : supprime les en-têtes X-WAF-* fournis par le
	// client. Doit précéder tout middleware qui lit ces en-têtes — le pipeline les
	// traite comme de l'état interne de confiance (X-WAF-Action: PASS vaut bypass
	// du challenge, du rate limiting, de l'intégrité et des règles). Seule la
	// capture FR-19 ci-dessous s'exécute en amont, et elle n'interprète rien.
	handler = ingress.Middleware(handler)
	// FR-19 : le token que l'upstream retransmet à /waf/origin/verify est le seul
	// X-WAF-* d'origine cliente à rester lisible. Capturé ici, donc en amont de
	// l'assainissement, et lu hors de r.Header — sans quoi l'oracle répondrait
	// 401 à tout token, valide compris. La valeur reste vérifiée par HMAC.
	if cfg.OriginProtection.Enabled {
		handler = origin.CaptureInboundToken(handler)
	}
	return handler
}

// envelopeGuard retourne les refus par IP et par Host appliqués à tout chemin
// servi, /waf/health excepté (sondes par IP) : une instance unique, pour que la
// borne slowloris par IP compte toutes les requêtes de l'IP, quel que soit le
// chemin. La chaîne "/" les monte sous le journal et les métriques.
func envelopeGuard(cfg config.Config) func(http.Handler) http.Handler {
	var limiter *slowloris.Limiter
	if cfg.Slowloris.Enabled {
		limiter = slowloris.New(cfg.Slowloris.MaxConnsPerIP)
	}
	return func(next http.Handler) http.Handler {
		// Host non déclaré refusé (ADR-020 option 1C, opt-in) : un Host non
		// listé hériterait sinon de la politique globale, y compris vers la
		// même origine qu'un domaine durci.
		if cfg.Server.StrictHost {
			next = proxy.StrictHost(cfg.Domains, next)
		}
		// Protection Slowloris (FR-23) : limite les requêtes concurrentes par IP.
		if limiter != nil {
			next = limiter.Handler(next)
		}
		return next
	}
}

// redirectToHTTPS renvoie un handler de redirection HTTP→HTTPS qui valide le
// Host entrant contre les domaines configurés avant de rediriger. Un Host non
// reconnu reçoit un 400 : sans cette garde, un attaquant peut injecter un Host
// arbitraire et forcer une redirection vers un domaine tiers (open-redirect).
func redirectToHTTPS(domains []config.DomainConfig) http.HandlerFunc {
	allowed := make([]string, len(domains))
	for i, d := range domains {
		allowed[i] = strings.ToLower(d.Host)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// Même normalisation que le routage : "Example.com" et "[::1]:8080"
		// étaient refusés en 400 (casse conservée, IPv6 coupé au premier ":").
		host := hostname.Normalize(r.Host)
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

// allowGet restreint un endpoint du WAF à GET (et HEAD) : enregistrés sans
// méthode, /waf/health, /waf/metrics et /waf/origin/verify répondaient 200 à
// un POST ou un DELETE. Un motif « GET /waf/health » ne suffit pas : les autres
// méthodes retomberaient sur « / », donc sur l'upstream.
func allowGet(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
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
