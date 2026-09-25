package httpbody

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Un corps non lu à la fermeture interdisait la réutilisation de la
// connexion : trois requêtes ouvraient trois connexions TCP.
func TestDrainKeepsConnectionReusable(t *testing.T) {
	var connections atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 4096))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	client := server.Client()
	for range 3 {
		response, err := client.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		Drain(response.Body)
		_ = response.Body.Close()
	}

	if got := connections.Load(); got != 1 {
		t.Fatalf("connections opened = %d, want 1 (keep-alive reused)", got)
	}
}

func TestDrainBoundsTheRead(t *testing.T) {
	body := &countingBody{remaining: 10 * maxDrainBytes}
	Drain(body)

	if body.read > maxDrainBytes {
		t.Fatalf("read %d bytes, want at most %d", body.read, maxDrainBytes)
	}
}

type countingBody struct {
	remaining int
	read      int
}

func (b *countingBody) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(p), b.remaining)
	b.remaining -= n
	b.read += n
	return n, nil
}
