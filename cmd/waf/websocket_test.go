package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/proxy"
)

// FR-01 : l'upgrade WebSocket traverse toute la chaîne, dont les wrappers de
// ResponseWriter (logger, métriques, anti-DDoS…) qui doivent laisser le proxy
// détourner la connexion.
func TestRoutesRelayWebSocketUpgradeThroughThePipeline(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buffered, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("upstream hijack: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = buffered.Flush()
		frame := make([]byte, 4)
		if _, err := io.ReadFull(buffered, frame); err == nil {
			_, _ = conn.Write(frame)
		}
	}))
	t.Cleanup(upstream.Close)

	cfg := config.Default()
	cfg.Cloudflare.Trusted = false
	cfg.Challenge.Enabled = false
	cfg.Upstream.Address = upstream.URL
	proxyHandler, err := proxy.NewHandler(cfg)
	if err != nil {
		t.Fatalf("proxy.NewHandler() error = %v", err)
	}
	server := httptest.NewServer(routes(cfg, newTestRules(t, nil, nil, nil), newTestLogger(), newTestMetrics(), newTestAntiDDoS(t), newTestRateLimiter(t, cfg), newTestAntiBot(t, cfg), nil, newTestChallenge(t, cfg), newTestScoreManager(t, cfg), nil, proxyHandler))
	t.Cleanup(server.Close)

	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte("GET /socket HTTP/1.1\r\nHost: example.test\r\nUser-Agent: Mozilla/5.0\r\nAccept-Language: fr\r\nAccept-Encoding: gzip\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"))
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101 through the whole pipeline", response.StatusCode)
	}
	_, _ = conn.Write([]byte("ping"))
	echo := make([]byte, 4)
	if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("tunnel = %q (%v), want ping", echo, err)
	}
}
