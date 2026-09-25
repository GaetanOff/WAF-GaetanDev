package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/hostname"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/upstream"
	"github.com/gaetandev/waf/internal/upstreamtime"
	"github.com/gaetandev/waf/internal/wafheader"
)

const defaultWAFScore = "50"

// sharedBuffers est partagé par tous les reverse proxies du process.
var sharedBuffers = newBufferPool()

type Handler struct {
	defaultUpstream *url.URL
	defaultProxy    *httputil.ReverseProxy
	domains         []domainRoute
	// exactHosts indexe les routes exactes : host normalisé → index de la
	// première entrée domains[] pour cet hôte. Les wildcards restent parcourus
	// dans l'ordre de config (wildcardRoutes).
	exactHosts     map[string]int
	wildcardRoutes []int
	proxies        map[string]*httputil.ReverseProxy

	pool        *upstream.Pool
	poolProxies map[string]*httputil.ReverseProxy
}

// WithPool active le load balancing : quand un pool est configuré, il sélectionne
// l'upstream par requête (health-aware, FR-25/26) et prend la priorité sur le
// routage par domaine. Un upstream qui échoue à la connexion est marqué non sain.
func (h *Handler) WithPool(pool *upstream.Pool, tlsVerify bool, maxIdleConns int, timeout time.Duration, preserveHost bool) error {
	proxies := make(map[string]*httputil.ReverseProxy, len(pool.Upstreams()))
	for _, u := range pool.Upstreams() {
		target, err := url.Parse(u.Address)
		if err != nil {
			return fmt.Errorf("parse pool upstream %q: %w", u.Address, err)
		}
		proxy := newReverseProxy(target, tlsVerify, maxIdleConns, timeout, preserveHost)
		member := u
		proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
			member.SetHealthy(false) // failover : exclure dès l'échec de connexion
			http.Error(w, "bad gateway", http.StatusBadGateway)
		}
		proxies[u.Address] = proxy
	}
	h.pool = pool
	h.poolProxies = proxies
	return nil
}

type domainRoute struct {
	host     string
	upstream *url.URL
	proxy    *httputil.ReverseProxy
	wildcard bool
}

func NewHandler(cfg config.Config) (*Handler, error) {
	defaultUpstream, err := url.Parse(cfg.Upstream.Address)
	if err != nil {
		return nil, fmt.Errorf("parse default upstream: %w", err)
	}

	timeout, err := time.ParseDuration(cfg.Upstream.Timeout)
	if err != nil {
		return nil, fmt.Errorf("parse upstream timeout: %w", err)
	}

	handler := &Handler{
		defaultUpstream: defaultUpstream,
		exactHosts:      make(map[string]int),
		proxies:         make(map[string]*httputil.ReverseProxy),
	}
	handler.defaultProxy = newReverseProxy(defaultUpstream, cfg.Upstream.TLSVerify, cfg.Upstream.MaxIdleConns, timeout, cfg.Upstream.PreserveHost)
	handler.proxies[defaultUpstream.String()] = handler.defaultProxy

	for _, domain := range cfg.Domains {
		upstream, err := url.Parse(domain.Upstream)
		if err != nil {
			return nil, fmt.Errorf("parse upstream for domain %q: %w", domain.Host, err)
		}

		route := domainRoute{
			host:     strings.ToLower(domain.Host),
			upstream: upstream,
			wildcard: strings.HasPrefix(domain.Host, "*."),
		}
		if route.wildcard {
			route.host = strings.TrimPrefix(route.host, "*.")
		}

		key := upstream.String()
		if _, exists := handler.proxies[key]; !exists {
			handler.proxies[key] = newReverseProxy(upstream, cfg.Upstream.TLSVerify, cfg.Upstream.MaxIdleConns, timeout, cfg.Upstream.PreserveHost)
		}
		route.proxy = handler.proxies[key]

		index := len(handler.domains)
		handler.domains = append(handler.domains, route)
		if route.wildcard {
			handler.wildcardRoutes = append(handler.wildcardRoutes, index)
		} else if _, exists := handler.exactHosts[route.host]; !exists {
			handler.exactHosts[route.host] = index // première entrée gagnante
		}
	}

	return handler, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Le temps passé dans proxy.ServeHTTP (round-trip upstream + streaming de la
	// réponse) est compté comme temps upstream, pour distinguer waf_latency_ms du
	// total. Recorder absent (chaîne sans logger) → Add est un no-op.
	recorder := upstreamtime.FromContext(r.Context())
	if h.pool != nil {
		member, ok := h.pool.Pick(realIP(r))
		if !ok {
			http.Error(w, "no healthy upstream", http.StatusBadGateway)
			return
		}
		member.Acquire()
		defer member.Release()
		started := time.Now()
		h.poolProxies[member.Address].ServeHTTP(w, r)
		recorder.Add(time.Since(started))
		return
	}

	proxy := h.resolveProxy(r.Host)
	started := time.Now()
	proxy.ServeHTTP(w, r)
	recorder.Add(time.Since(started))
}

// resolveProxy retourne le proxy de la première entrée domains[] qui
// correspond à l'hôte, sinon celui de l'upstream par défaut.
//
// Le proxy était retrouvé par h.proxies[target.String()] — une URL
// resérialisée à chaque requête — après un parcours linéaire de toutes les
// routes. Les hôtes exacts sont désormais indexés ; seuls les wildcards
// antérieurs à la correspondance exacte sont encore parcourus, ce qui préserve
// la règle « première entrée gagnante ».
func (h *Handler) resolveProxy(host string) *httputil.ReverseProxy {
	if index := h.routeIndex(hostname.Normalize(host)); index >= 0 {
		return h.domains[index].proxy
	}
	return h.defaultProxy
}

func (h *Handler) routeIndex(host string) int {
	best, exact := h.exactHosts[host]
	if !exact {
		best = -1
	}
	for _, index := range h.wildcardRoutes {
		if exact && index > best {
			break
		}
		if h.domains[index].matches(host) {
			return index
		}
	}
	return best
}

func (r domainRoute) matches(host string) bool {
	if r.wildcard {
		return host == r.host || strings.HasSuffix(host, "."+r.host)
	}

	return host == r.host
}

func newReverseProxy(target *url.URL, tlsVerify bool, maxIdleConns int, timeout time.Duration, preserveHost bool) *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{BufferPool: sharedBuffers}
	// Rewrite remplace Director (déprécié depuis Go 1.26). SetURL route vers
	// l'upstream (scheme/host/path) et fixe l'hôte sortant ; SetXForwarded
	// préserve les en-têtes X-Forwarded-* que l'ancien director ajoutait.
	proxy.Rewrite = func(pr *httputil.ProxyRequest) {
		clientIP := realIP(pr.In)
		inHost := pr.In.Host
		pr.SetURL(target)
		pr.SetXForwarded()
		// Par défaut, l'hôte sortant est celui de l'upstream. Avec preserveHost,
		// on conserve le Host entrant pour que l'upstream route par vhost.
		if preserveHost {
			pr.Out.Host = inHost
		} else {
			pr.Out.Host = target.Host
		}
		pr.Out.Header.Set("X-Real-IP", clientIP)
		if pr.Out.Header.Get(wafheader.Score) == "" {
			pr.Out.Header.Set(wafheader.Score, defaultWAFScore)
		}
	}
	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          maxIdleConns,
		MaxIdleConnsPerHost:   maxIdleConns,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !tlsVerify,
			MinVersion:         tls.VersionTLS12,
		},
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	return proxy
}

func realIP(r *http.Request) string {
	if ip := cloudflare.RealIP(r); ip != "" {
		return ip
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
