package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gaetandev/waf/internal/config"
)

// admin-api.feature — « Brute-force — IP verrouillée après trop d'échecs ».
func TestAdminLocksOutIPAfterRepeatedFailures(t *testing.T) {
	server := newTestServer(t)
	handler := server.Handler()
	for range server.cfg.SelfProtection.AdminMaxFailures {
		request := requestWithAuth(http.MethodGet, "/waf/stats", "")
		request.Header.Set("Authorization", "Bearer wrong-token")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", response.Code)
		}
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestWithAuth(http.MethodGet, "/waf/stats", ""))

	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
		t.Fatalf("status = %d Retry-After = %q, want 429 with Retry-After even with the right token", response.Code, response.Header().Get("Retry-After"))
	}
}

// admin-api.feature — « Brute-force IPv6 — verrouillage par préfixe /64 ».
func TestAdminLocksOutIPv6ByPrefix(t *testing.T) {
	server := newTestServer(t)
	handler := server.Handler()
	for i := range server.cfg.SelfProtection.AdminMaxFailures {
		request := requestWithAuth(http.MethodGet, "/waf/stats", "")
		request.RemoteAddr = fmt.Sprintf("[2001:db8:1:2::%x]:1234", i+1)
		request.Header.Set("Authorization", "Bearer wrong-token")
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}

	request := requestWithAuth(http.MethodGet, "/waf/stats", "")
	request.RemoteAddr = "[2001:db8:1:2:ffff::1]:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429: failures from the same /64 must share one lockout", response.Code)
	}
}

// admin-api.feature — « Pagination — bornes » : une page hors bornes rend une
// liste vide, sans débordement de (page-1)*limit.
func TestAdminPaginationSurvivesHugePage(t *testing.T) {
	server := newTestServer(t)
	server.scores.Set("10.0.0.1", "example.test", 50)
	for _, query := range []string{"?page=9223372036854775807&limit=1000", "?page=9223372036854775807", "?page=4611686018427387904&limit=2"} {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, requestWithAuth(http.MethodGet, "/waf/admin/visitors"+query, ""))

		var body listResponse[VisitorInfo]
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatalf("%s: status %d, decode: %v", query, response.Code, err)
		}
		if response.Code != http.StatusOK || len(body.Items) != 0 || body.Total != 1 {
			t.Fatalf("%s: status %d, %d items total %d, want 200 with 0 of 1", query, response.Code, len(body.Items), body.Total)
		}
	}
}

// admin-api.feature — « Pagination des listes » et « Pagination — bornes ».
func TestAdminPaginatesLists(t *testing.T) {
	server := newTestServer(t)
	for i := range 5 {
		server.scores.Set(fmt.Sprintf("10.0.0.%d", i), "example.test", 50+i)
	}
	page := func(query string) listResponse[VisitorInfo] {
		t.Helper()
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, requestWithAuth(http.MethodGet, "/waf/admin/visitors"+query, ""))
		var body listResponse[VisitorInfo]
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatalf("decode %s: %v", query, err)
		}
		return body
	}

	if body := page("?page=2&limit=2"); len(body.Items) != 2 || body.Total != 5 {
		t.Fatalf("page 2 = %d items total %d, want 2 of 5", len(body.Items), body.Total)
	}
	if body := page("?page=4&limit=2"); len(body.Items) != 0 || body.Total != 5 {
		t.Fatalf("page 4 = %d items total %d, want 0 of 5", len(body.Items), body.Total)
	}
	if body := page("?page=0&limit=-1"); len(body.Items) != 5 {
		t.Fatalf("defaults = %d items, want all 5 (page 1, limit 50)", len(body.Items))
	}
	sorted := page("?sort=score_asc")
	for i := 1; i < len(sorted.Items); i++ {
		if sorted.Items[i-1].Score > sorted.Items[i].Score {
			t.Fatalf("sort=score_asc not ascending: %+v", sorted.Items)
		}
	}
}

func TestAdminPaginationCapsLimit(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://admin.test/x?limit=5000", nil)
	items := make([]int, 1500)
	if body := paged(items, request); len(body.Items) != 1000 || body.Total != 1500 {
		t.Fatalf("limit=5000 → %d items total %d, want 1000 of 1500", len(body.Items), body.Total)
	}
}

// Le Retry-After du verrouillage suit self_protection.admin_lockout : il
// valait 300 quelle que soit la durée configurée.
func TestAdminLockoutRetryAfterFollowsTheConfiguredLockout(t *testing.T) {
	server := newTestServerWith(t, func(cfg *config.Config) { cfg.SelfProtection.AdminLockout = "90s" })
	handler := server.Handler()
	for range server.cfg.SelfProtection.AdminMaxFailures {
		request := requestWithAuth(http.MethodGet, "/waf/stats", "")
		request.Header.Set("Authorization", "Bearer wrong-token")
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestWithAuth(http.MethodGet, "/waf/stats", ""))

	retryAfter, err := strconv.Atoi(response.Header().Get("Retry-After"))
	if response.Code != http.StatusTooManyRequests || err != nil || retryAfter < 1 || retryAfter > 90 {
		t.Fatalf("status = %d, Retry-After = %q; want 429 and 1..90 seconds", response.Code, response.Header().Get("Retry-After"))
	}
}
