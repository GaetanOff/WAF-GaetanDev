package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
)

// slowloris-protection.feature, « Slowloris — en-têtes jamais terminés dans le
// délai » : le serveur ferme la connexion sans réponse, aucun 408.
func TestHeaderTimeoutClosesTheConnectionWithoutResponse(t *testing.T) {
	cfg := config.Default()
	cfg.Slowloris.HeaderTimeout = "200ms"
	timeouts, err := parseServerTimeouts(cfg)
	if err != nil {
		t.Fatalf("parseServerTimeouts: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("handler reached with incomplete headers")
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ReadHeaderTimeout = timeouts.header
	server.Start()
	defer server.Close()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	started := time.Now()
	reply, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v (the connection was not closed by the server)", err)
	}
	if len(reply) != 0 {
		t.Fatalf("server replied %q, want the connection closed without response", reply)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("connection closed after %s, want about header_timeout", elapsed)
	}
}

// slowloris-protection.feature, « header_timeout s'applique même slowloris
// désactivé ».
func TestHeaderTimeoutDefaultsWhenSlowlorisIsDisabled(t *testing.T) {
	cfg := config.Default()
	cfg.Slowloris.Enabled = false
	cfg.Slowloris.HeaderTimeout = "1h"
	timeouts, err := parseServerTimeouts(cfg)
	if err != nil {
		t.Fatalf("parseServerTimeouts: %v", err)
	}
	if timeouts.header != defaultHeaderTimeout {
		t.Fatalf("header timeout = %s, want %s", timeouts.header, defaultHeaderTimeout)
	}
}
