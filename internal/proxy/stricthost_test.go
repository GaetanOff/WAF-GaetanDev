package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gaetandev/waf/internal/config"
)

func TestStrictHostServesOnlyDeclaredHosts(t *testing.T) {
	domains := []config.DomainConfig{{Host: "boxaria.fr"}, {Host: "*.example.com"}}
	handler := StrictHost(domains, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	tests := []struct {
		name string
		host string
		path string
		want int
	}{
		{name: "exact host", host: "boxaria.fr", path: "/", want: http.StatusNoContent},
		{name: "case and port ignored", host: "BOXARIA.fr:8443", path: "/", want: http.StatusNoContent},
		{name: "wildcard subdomain", host: "api.example.com", path: "/", want: http.StatusNoContent},
		{name: "wildcard covers the apex", host: "example.com", path: "/", want: http.StatusNoContent},
		{name: "unlisted host", host: "peu-importe.test", path: "/", want: http.StatusBadRequest},
		{name: "WAF IP as host", host: "203.0.113.10:8080", path: "/", want: http.StatusBadRequest},
		{name: "suffix is not a subdomain", host: "evilexample.com", path: "/", want: http.StatusBadRequest},
		{name: "health stays served", host: "10.0.0.5:8080", path: "/waf/health", want: http.StatusNoContent},
		{name: "metrics are not exempt", host: "10.0.0.5:8080", path: "/waf/metrics", want: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://placeholder"+tt.path, nil)
			request.Host = tt.host
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != tt.want {
				t.Fatalf("status = %d, want %d", response.Code, tt.want)
			}
			if tt.want == http.StatusBadRequest && response.Header().Get("X-WAF-Reason") != "host_not_declared" {
				t.Fatalf("X-WAF-Reason = %q, want host_not_declared", response.Header().Get("X-WAF-Reason"))
			}
		})
	}
}
