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

// ADR-019 option B : un CF-* hors plage Cloudflare est supprimé, pas rejeté.
func TestMiddlewareStripsInfrastructureHeadersFromNonCloudflareSource(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "203.0.113.10:443"
	request.Header.Set("CF-IPCountry", "FR")
	request.Header.Set("Cf-Bot-Management-Ja3Hash", "e7d705a3286e19ea42f587b344ee6865")
	request.Header.Set("CF-Ray", "forged-ray")
	request.Header.Set("X-Other", "kept")

	var forwarded http.Header
	response := httptest.NewRecorder()
	Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Clone()
	})).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (strip, not reject)", response.Code)
	}
	for _, name := range []string{"CF-IPCountry", "Cf-Bot-Management-Ja3Hash", "CF-Ray"} {
		if value := forwarded.Get(name); value != "" {
			t.Fatalf("%s = %q forwarded from a non-Cloudflare source, want it stripped", name, value)
		}
	}
	if forwarded.Get("X-Other") != "kept" {
		t.Fatal("non-infrastructure header stripped, want it kept")
	}
}

func TestMiddlewareKeepsInfrastructureHeadersFromCloudflare(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "173.245.48.10:443"
	request.Header.Set(connectingIPHeader, "198.51.100.25")
	request.Header.Set("CF-IPCountry", "FR")

	var country string
	Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		country = r.Header.Get("CF-IPCountry")
	})).ServeHTTP(httptest.NewRecorder(), request)

	if country != "FR" {
		t.Fatalf("CF-IPCountry = %q, want FR kept from a Cloudflare source", country)
	}
}

func TestStripUntrustedRemovesEveryInfrastructureHeader(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "173.245.48.10:443" // même depuis une plage Cloudflare
	request.Header.Set("CF-IPCountry", "FR")
	request.Header.Set(connectingIPHeader, "198.51.100.25")

	var forwarded http.Header
	StripUntrusted(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Clone()
	})).ServeHTTP(httptest.NewRecorder(), request)

	if len(forwarded) != 0 {
		t.Fatalf("headers = %v, want every CF-* stripped when cloudflare.trusted is false", forwarded)
	}
}
