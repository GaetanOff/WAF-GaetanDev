package geo

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gaetandev/waf/internal/config"
)

func handlerWith(cfg config.Geo) (http.Handler, *bool) {
	called := new(bool)
	h := NewRules(cfg).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	return h, called
}

func requestFromCountry(country string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	if country != "" {
		request.Header.Set("CF-IPCountry", country)
	}
	return request
}

func TestGeoBlocksBlockedCountry(t *testing.T) {
	h, called := handlerWith(config.Geo{Enabled: true, BlockedCountries: []string{"RU"}})
	response := httptest.NewRecorder()
	h.ServeHTTP(response, requestFromCountry("RU"))

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if *called {
		t.Fatal("blocked country must not reach upstream")
	}
	if response.Header().Get("X-WAF-Reason") != "geo_country_blocked" {
		t.Fatalf("reason = %q", response.Header().Get("X-WAF-Reason"))
	}
}

func TestGeoWhitelistRejectsOtherCountries(t *testing.T) {
	h, _ := handlerWith(config.Geo{Enabled: true, AllowedCountries: []string{"FR"}})

	allowed := httptest.NewRecorder()
	h.ServeHTTP(allowed, requestFromCountry("FR"))
	if allowed.Code != http.StatusNoContent {
		t.Fatalf("FR status = %d, want 204", allowed.Code)
	}

	rejected := httptest.NewRecorder()
	h.ServeHTTP(rejected, requestFromCountry("US"))
	if rejected.Code != http.StatusForbidden {
		t.Fatalf("US status = %d, want 403", rejected.Code)
	}
}

func TestGeoChallengeCountryPublishesContribution(t *testing.T) {
	cfg := config.Geo{Enabled: true, ChallengeCountries: []string{"CN"}, ChallengeContribution: 60}
	var contribution string
	h := NewRules(cfg).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contribution = r.Header.Get("X-WAF-Risk-geo")
		w.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	h.ServeHTTP(response, requestFromCountry("CN"))

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (challenge contributes, not blocks)", response.Code)
	}
	if contribution != "60" {
		t.Fatalf("X-WAF-Risk-geo = %q, want 60", contribution)
	}
}

func TestGeoIgnoredWhenCountryHeaderAbsent(t *testing.T) {
	h, called := handlerWith(config.Geo{Enabled: true, BlockedCountries: []string{"FR"}})
	response := httptest.NewRecorder()
	h.ServeHTTP(response, requestFromCountry("")) // pas de CF-IPCountry

	if !*called || response.Code != http.StatusNoContent {
		t.Fatalf("missing CF-IPCountry must pass gracefully: called=%v status=%d", *called, response.Code)
	}
}
