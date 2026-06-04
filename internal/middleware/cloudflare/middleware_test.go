package cloudflare

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddlewareUsesConnectingIPFromCloudflareSource(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "173.245.48.10:443"
	request.Header.Set(connectingIPHeader, "198.51.100.25")

	var gotRealIP string
	handler := Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotRealIP = RealIP(r)
	}))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if gotRealIP != "198.51.100.25" {
		t.Fatalf("RealIP() = %q, want CF-Connecting-IP", gotRealIP)
	}
}

func TestMiddlewareRejectsForgedConnectingIPFromNonCloudflareSource(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "203.0.113.10:443"
	request.Header.Set(connectingIPHeader, "198.51.100.25")

	response := httptest.NewRecorder()
	Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not be called")
	})).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
}

func TestMiddlewareUsesRemoteIPWithoutConnectingIPHeader(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "203.0.113.10:443"

	var gotRealIP string
	handler := Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotRealIP = RealIP(r)
	}))

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if gotRealIP != "203.0.113.10" {
		t.Fatalf("RealIP() = %q, want remote IP", gotRealIP)
	}
}

func TestMiddlewareRejectsInvalidConnectingIPHeader(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "173.245.48.10:443"
	request.Header.Set(connectingIPHeader, "not-an-ip")

	response := httptest.NewRecorder()
	Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not be called")
	})).ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
}

func TestIsCloudflareIPSupportsIPv6(t *testing.T) {
	ip, err := remoteIP("[2606:4700::1]:443")
	if err != nil {
		t.Fatalf("remoteIP() error = %v", err)
	}
	if !IsCloudflareIP(ip) {
		t.Fatalf("expected %s to be a Cloudflare IP", ip)
	}
}
