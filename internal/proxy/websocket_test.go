package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// FR-01 (reverse-proxy.feature, « WebSocket — upgrade HTTP relayé dans les
// deux sens ») : l'upgrade traverse le proxy et le tunnel relaie les octets.
func TestHandlerRelaysWebSocketUpgrade(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "upgrade required", http.StatusUpgradeRequired)
			return
		}
		conn, buffered, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = buffered.Flush()
		frame := make([]byte, 4)
		if _, err := io.ReadFull(buffered, frame); err != nil {
			return
		}
		_, _ = conn.Write([]byte("echo:" + string(frame)))
	}))
	t.Cleanup(upstream.Close)
	server := httptest.NewServer(newTestHandler(t, upstream.URL, nil))
	t.Cleanup(server.Close)

	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte("GET /socket HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"))

	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", response.StatusCode)
	}
	_, _ = conn.Write([]byte("ping"))
	echo := make([]byte, len("echo:ping"))
	if _, err := io.ReadFull(reader, echo); err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if string(echo) != "echo:ping" {
		t.Fatalf("tunnel = %q, want echo:ping", echo)
	}
}
