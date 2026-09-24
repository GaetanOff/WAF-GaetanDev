package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
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
