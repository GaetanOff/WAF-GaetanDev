package main

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/hostname"
	"github.com/gaetandev/waf/internal/maintenance"
	"github.com/gaetandev/waf/internal/middleware/access"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/middleware/ingress"
	"github.com/gaetandev/waf/internal/origin"
	"github.com/gaetandev/waf/internal/proxy"
	"github.com/gaetandev/waf/internal/secheaders"
	"github.com/gaetandev/waf/internal/selfprotect"
	"github.com/gaetandev/waf/internal/slowloris"
	"github.com/gaetandev/waf/internal/staticassets"
)

// routes assemble le handler du listener public à partir des composants que
// build a construits : endpoints /waf/*, puis la chaîne de protection devant
// l'origine. Elle prenait ces douze composants en paramètres, alors que app les
// porte déjà tous.
func (a *app) routes() http.Handler {
	cfg := *a.cfg
	proxyHandler := a.origin
	guard := envelopeGuard(cfg)
	mux := http.NewServeMux()
	mux.Handle("/waf/health", allowGet(http.HandlerFunc(healthHandler)))
	mux.Handle("/waf/metrics", guard(allowGet(a.metrics.Handler())))
	if cfg.OriginProtection.Enabled {
		// Protection de l'origine (FR-19) : endpoint de vérification + injection
		// du token signé vers l'upstream (le proxy transmet le header).
		signer := origin.NewSigner(cfg.OriginProtection.Secret)
		mux.Handle("/waf/origin/verify", guard(allowGet(http.HandlerFunc(signer.VerifyHandler))))
		proxyHandler = signer.Injector(proxyHandler)
	}
	// FR-34 / FR-04 : une décision CHALLENGE du moteur de risque ou du trust score
	// sert la page de challenge. Monté en aval de ces décisions, donc ici.
	proxyHandler = a.challengeMiddleware.Enforcer(proxyHandler)
	if cfg.RiskEngine.Enabled && a.riskMiddleware != nil {
		proxyHandler = a.riskMiddleware.Handler(proxyHandler)
	} else {
		proxyHandler = a.scoreManager.Middleware(proxyHandler)
	}
	// Détecteurs avancés exécutés juste avant le moteur de risque (wrap en ordre
	// inverse pour préserver l'ordre d'exécution detectors[0], detectors[1], ...).
	for _, detector := range slices.Backward(a.detectors) {
		proxyHandler = detector(proxyHandler)
	}
	proxyHandler = a.antiBot.Handler(proxyHandler)
	// Rate limit et challenge sont montés en permanence : rate_limit.enabled et
	// challenge.enabled sont modifiables à chaud (PATCH /waf/admin/config), et
	// chaque middleware lit son réglage courant par requête. La décision de
	// challenge par hôte (FR-06) est prise dans le middleware.
	proxyHandler = a.rateLimiter.Handler(proxyHandler)
	proxyHandler = a.challengeMiddleware.Handler(proxyHandler)
	proxyHandler = a.antiDDoS.Handler(proxyHandler)
	proxyHandler = access.Middleware(a.accessRules, proxyHandler)
	// Auto-protection (FR-30) : limite le flood de POST /waf/verify par IP.
	if cfg.SelfProtection.Enabled {
		verifyWindow := selfprotect.NewWindow(cfg.SelfProtection.VerifyMaxPerMinute, time.Minute)
		proxyHandler = selfprotect.PathGuard("/waf/verify", verifyWindow)(proxyHandler)
	}
	// Refus d'enveloppe (slowloris, strict_host) et auto-protection sous le
	// journal et les métriques : montés au-dessus, leurs 429 et 400 n'étaient
	// ni comptés dans Prometheus, ni journalisés, ni publiés sur le flux admin.
	proxyHandler = guard(proxyHandler)
	proxyHandler = a.securityLogger.Middleware(a.scoreManager, proxyHandler)
	proxyHandler = a.metrics.Middleware(a.scoreManager, proxyHandler)
	// Bypass des assets statiques (FR-24) : le plus en amont du pipeline pour
	// marquer PASS avant challenge/trust/détecteurs (la blacklist reste appliquée).
	if cfg.StaticAssets.Enabled {
		proxyHandler = staticassets.New(cfg.StaticAssets).WithCounter(a.metrics.IncAssetRequest).Handler(proxyHandler)
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
