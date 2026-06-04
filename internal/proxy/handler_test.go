package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
)

func TestHandlerProxiesRequestAndAddsHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertHeader(t, r, "X-Real-IP", "127.0.0.1")
		assertHeader(t, r, "X-WAF-Score", "50")
		if forwardedFor := r.Header.Get("X-Forwarded-For"); !strings.Contains(forwardedFor, "127.0.0.1") {
			t.Fatalf("X-Forwarded-For = %q, want client IP", forwardedFor)
		}
		if r.Header.Get("X-Custom") != "preserved" {
			t.Fatalf("expected custom header to be preserved")
		}
		if r.URL.Path != "/orders/1" {
			t.Fatalf("path = %q, want /orders/1", r.URL.Path)
		}
		_, _ = w.Write([]byte("proxied"))
	}))
	t.Cleanup(upstream.Close)

	handler := newTestHandler(t, upstream.URL, nil)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	request, err := http.NewRequest(http.MethodGet, server.URL+"/orders/1", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("X-Custom", "preserved")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("request proxy: %v", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "proxied" {
		t.Fatalf("body = %q, want proxied", string(body))
	}
}

func TestHandlerRoutesByDomain(t *testing.T) {
	defaultUpstream := namedUpstream(t, "default")
	exactUpstream := namedUpstream(t, "exact")
	wildcardUpstream := namedUpstream(t, "wildcard")

	handler := newTestHandler(t, defaultUpstream.URL, []config.DomainConfig{
		{Host: "app.example.com", Upstream: exactUpstream.URL},
		{Host: "*.example.net", Upstream: wildcardUpstream.URL},
	})

	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "exact", host: "app.example.com", want: "exact"},
		{name: "wildcard", host: "api.example.net", want: "wildcard"},
		{name: "default", host: "unknown.example.org", want: "default"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://"+tt.host+"/", nil)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Body.String() != tt.want {
				t.Fatalf("body = %q, want %q", response.Body.String(), tt.want)
			}
		})
	}
}

func TestHandlerReturnsBadGatewayWhenUpstreamIsDown(t *testing.T) {
	handler := newTestHandler(t, "http://127.0.0.1:1", nil)
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", response.Code)
	}
}

func newTestHandler(t *testing.T, upstream string, domains []config.DomainConfig) *Handler {
	t.Helper()

	cfg := config.Default()
	cfg.Version = "1.0"
	cfg.Server.Listen = ":0"
	cfg.Upstream.Address = upstream
	cfg.Upstream.Timeout = "1s"
	cfg.Upstream.MaxIdleConns = 10
	cfg.Challenge.Enabled = false
	cfg.Admin.Enabled = false
	cfg.Domains = domains

	handler, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

func namedUpstream(t *testing.T, name string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(name))
	}))
	t.Cleanup(server.Close)

	return server
}

func assertHeader(t *testing.T, r *http.Request, name, want string) {
	t.Helper()

	if got := r.Header.Get(name); got != want {
		t.Fatalf("%s = %q, want %q", name, got, want)
	}
}

func TestNormalizeHostStripsPort(t *testing.T) {
	got := normalizeHost("Example.COM:8080")
	if got != "example.com" {
		t.Fatalf("normalizeHost() = %q, want example.com", got)
	}
}

func TestTransportTimeoutIsConfigured(t *testing.T) {
	handler := newTestHandler(t, "http://127.0.0.1:1", nil)
	transport, ok := handler.proxies[handler.defaultUpstream.String()].Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected http.Transport")
	}
	if transport.ResponseHeaderTimeout != time.Second {
		t.Fatalf("ResponseHeaderTimeout = %s, want 1s", transport.ResponseHeaderTimeout)
	}
}
