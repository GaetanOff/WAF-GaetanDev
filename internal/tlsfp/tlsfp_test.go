package tlsfp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gaetandev/waf/internal/config"
)

func TestJA3StringAndHash(t *testing.T) {
	ja3 := JA3String(771, []uint16{4865, 4866, 4867}, []uint16{0, 23, 65281}, []uint16{29, 23, 24}, []uint8{0})
	want := "771,4865-4866-4867,0-23-65281,29-23-24,0"
	if ja3 != want {
		t.Fatalf("JA3String = %q, want %q", ja3, want)
	}
	hash := JA3Hash(ja3)
	if len(hash) != 32 {
		t.Fatalf("JA3Hash length = %d, want 32 (md5 hex)", len(hash))
	}
	if JA3Hash(ja3) != hash {
		t.Fatal("JA3Hash is not deterministic")
	}
}

func requestWithJA3(ip string, ja3 string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = ip + ":1234"
	if ja3 != "" {
		request.Header.Set("Cf-Bot-Management-Ja3Hash", ja3)
	}
	return request
}

func TestBlacklistedJA3SetsDeterministicTrigger(t *testing.T) {
	m := NewMiddleware(config.TLSFingerprint{Enabled: true, JA3Blacklist: []string{"deadbeef"}})
	var trigger string
	m.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trigger = r.Header.Get("X-WAF-Deterministic-Trigger")
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), requestWithJA3("1.2.3.4", "DEADBEEF"))

	if trigger != "ja3_blacklist" {
		t.Fatalf("trigger = %q, want ja3_blacklist", trigger)
	}
}

func TestJA3SwapPublishesContribution(t *testing.T) {
	m := NewMiddleware(config.TLSFingerprint{Enabled: true, SwapContribution: 50})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	// Première session : pas de swap.
	first := requestWithJA3("1.2.3.4", "aaaa")
	m.Handler(next).ServeHTTP(httptest.NewRecorder(), first)
	if first.Header.Get("X-WAF-Risk-tls") != "" {
		t.Fatal("first session must not be a swap")
	}

	// Deuxième session, JA3 différent → swap détecté.
	second := requestWithJA3("1.2.3.4", "bbbb")
	m.Handler(next).ServeHTTP(httptest.NewRecorder(), second)
	if second.Header.Get("X-WAF-Risk-tls") != "50" {
		t.Fatalf("X-WAF-Risk-tls = %q, want 50 (swap)", second.Header.Get("X-WAF-Risk-tls"))
	}
}

func TestNoJA3HeaderPassesGracefully(t *testing.T) {
	m := NewMiddleware(config.TLSFingerprint{Enabled: true, JA3Blacklist: []string{"deadbeef"}})
	called := false
	m.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), requestWithJA3("1.2.3.4", ""))

	if !called {
		t.Fatal("missing JA3 header must pass gracefully")
	}
}
