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
)

const defaultWAFScore = "50"

type Handler struct {
	defaultUpstream *url.URL
	domains         []domainRoute
	proxies         map[string]*httputil.ReverseProxy
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
	handler.proxies[defaultUpstream.String()] = newReverseProxy(defaultUpstream, cfg.Upstream.TLSVerify, cfg.Upstream.MaxIdleConns, timeout)

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
			handler.proxies[key] = newReverseProxy(upstream, cfg.Upstream.TLSVerify, cfg.Upstream.MaxIdleConns, timeout)
		}
	}

	return handler, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upstream := h.resolveUpstream(r.Host)
	proxy := h.proxies[upstream.String()]
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

func newReverseProxy(target *url.URL, tlsVerify bool, maxIdleConns int, timeout time.Duration) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		clientIP := realIP(r)
		originalDirector(r)
		r.Host = target.Host
		r.Header.Set("X-Real-IP", clientIP)
		if r.Header.Get("X-WAF-Score") == "" {
			r.Header.Set("X-WAF-Score", defaultWAFScore)
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
