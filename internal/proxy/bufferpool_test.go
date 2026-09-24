package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gaetandev/waf/internal/config"
)

func TestReverseProxiesShareTheBufferPool(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 100*1024)))
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.Upstream.Address = upstream.URL
	handler, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	for _, proxy := range handler.proxies {
		if proxy.BufferPool != sharedBuffers {
			t.Fatal("reverse proxy without the shared BufferPool allocates 32 KiB per request")
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://example.test/", nil))
	if response.Body.Len() != 100*1024 {
		t.Fatalf("body = %d bytes, want 102400 copied through pooled buffers", response.Body.Len())
	}
}

func TestBufferPoolRecyclesNominalBuffersOnly(t *testing.T) {
	pool := newBufferPool()
	buffer := pool.Get()
	if len(buffer) != copyBufferSize {
		t.Fatalf("len = %d, want %d", len(buffer), copyBufferSize)
	}
	pool.Put(buffer)
	pool.Put(make([]byte, 10)) // ignoré : jamais servi à un ReverseProxy
	if got := pool.Get(); len(got) != copyBufferSize {
		t.Fatalf("len = %d, want %d", len(got), copyBufferSize)
	}
}

func BenchmarkProxyServeHTTP(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	cfg := config.Default()
	cfg.Upstream.Address = upstream.URL
	handler, err := NewHandler(cfg)
	if err != nil {
		b.Fatalf("NewHandler() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	b.ReportAllocs()
	for b.Loop() {
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}
}
