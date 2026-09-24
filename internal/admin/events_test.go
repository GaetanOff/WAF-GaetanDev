package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/logger"
)

func securityEventAt(at time.Time, action string, domain string) logger.SecurityEvent {
	return logger.SecurityEvent{
		Timestamp: at.UTC().Format(time.RFC3339Nano),
		RequestID: "req-" + action,
		IP:        "203.0.113.0",
		Domain:    domain,
		Method:    http.MethodGet,
		Path:      "/",
		Action:    action,
		Reason:    "test",
	}
}

func listEvents(t *testing.T, server *Server, query string) listResponse[SecurityEventSummary] {
	t.Helper()
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, requestWithAuth(http.MethodGet, "/waf/admin/events"+query, ""))
	if response.Code != http.StatusOK {
		t.Fatalf("GET events%s: status = %d body = %s", query, response.Code, response.Body.String())
	}
	var body listResponse[SecurityEventSummary]
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body
}

// Régression : recentEvents n'avait aucun writer, le flux était toujours vide.
func TestAdminEventsServesRecordedMitigations(t *testing.T) {
	server := newTestServer(t)
	now := time.Now()
	recorder := server.EventRecorder()
	recorder.RecordSecurityEvent(securityEventAt(now.Add(-2*time.Second), logger.ActionBlock, "a.test"))
	recorder.RecordSecurityEvent(securityEventAt(now.Add(-time.Second), logger.ActionPass, "a.test"))
	recorder.RecordSecurityEvent(securityEventAt(now, logger.ActionRateLimit, "b.test"))

	body := listEvents(t, server, "")
	if body.Total != 2 || body.Items[0].Action != logger.ActionRateLimit || body.Items[1].Action != logger.ActionBlock {
		t.Fatalf("events = %+v, want RATE_LIMIT then BLOCK (newest first, PASS not retained)", body)
	}
	if filtered := listEvents(t, server, "?domain=a.test&action=BLOCK"); filtered.Total != 1 {
		t.Fatalf("filtered events = %+v, want the BLOCK on a.test", filtered)
	}
	since := now.Add(-1500 * time.Millisecond).UTC().Format(time.RFC3339Nano)
	if recent := listEvents(t, server, "?since="+since); recent.Total != 1 {
		t.Fatalf("events since %s = %+v, want 1", since, recent)
	}
}

func TestAdminEventsRejectsInvalidSince(t *testing.T) {
	server := newTestServer(t)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, requestWithAuth(http.MethodGet, "/waf/admin/events?since=yesterday", ""))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", response.Code)
	}
}

func TestEventLogIsBoundedAndDropsExpiredEvents(t *testing.T) {
	log := newEventLog()
	now := time.Now()
	log.RecordSecurityEvent(securityEventAt(now.Add(-25*time.Hour), logger.ActionBlock, "old.test"))
	for range maxRecentEvents + 5 {
		log.RecordSecurityEvent(securityEventAt(now, logger.ActionBlock, "new.test"))
	}
	recent := log.Recent(time.Time{})
	if len(recent) != maxRecentEvents {
		t.Fatalf("events kept = %d, want the %d most recent", len(recent), maxRecentEvents)
	}

	log = newEventLog()
	log.RecordSecurityEvent(securityEventAt(now.Add(-25*time.Hour), logger.ActionBlock, "old.test"))
	if recent := log.Recent(time.Time{}); len(recent) != 0 {
		t.Fatalf("events = %+v, want none older than 24h", recent)
	}
}
