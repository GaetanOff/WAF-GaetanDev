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
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/upstream"
)

const defaultWAFScore = "50"

type Handler struct {
	defaultUpstream *url.URL
	domains         []domainRoute
	proxies         map[string]*httputil.ReverseProxy

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
		proxies:         make(map[string]*httputil.ReverseProxy),
	}
	handler.proxies[defaultUpstream.String()] = newReverseProxy(defaultUpstream, cfg.Upstream.TLSVerify, cfg.Upstream.MaxIdleConns, timeout, cfg.Upstream.PreserveHost)

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
		handler.domains = append(handler.domains, route)

		key := upstream.String()
		if _, exists := handler.proxies[key]; !exists {
			handler.proxies[key] = newReverseProxy(upstream, cfg.Upstream.TLSVerify, cfg.Upstream.MaxIdleConns, timeout, cfg.Upstream.PreserveHost)
		}
	}

	return handler, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.pool != nil {
		member, ok := h.pool.Pick(realIP(r))
		if !ok {
			http.Error(w, "no healthy upstream", http.StatusBadGateway)
			return
		}
		member.Acquire()
		defer member.Release()
		h.poolProxies[member.Address].ServeHTTP(w, r)
		return
	}

	target := h.resolveUpstream(r.Host)
	proxy := h.proxies[target.String()]
	proxy.ServeHTTP(w, r)
}

func (h *Handler) resolveUpstream(host string) *url.URL {
	requestHost := normalizeHost(host)
	for _, route := range h.domains {
		if route.matches(requestHost) {
			return route.upstream
		}
	}

	return h.defaultUpstream
}

func (r domainRoute) matches(host string) bool {
	if r.wildcard {
		return host == r.host || strings.HasSuffix(host, "."+r.host)
	}

	return host == r.host
}

func newReverseProxy(target *url.URL, tlsVerify bool, maxIdleConns int, timeout time.Duration, preserveHost bool) *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{}
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
		if pr.Out.Header.Get("X-WAF-Score") == "" {
			pr.Out.Header.Set("X-WAF-Score", defaultWAFScore)
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

func normalizeHost(host string) string {
	hostname, _, err := net.SplitHostPort(host)
	if err == nil {
		return strings.ToLower(hostname)
	}
	return strings.ToLower(host)
}
