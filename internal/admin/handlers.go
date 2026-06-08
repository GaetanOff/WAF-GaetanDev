package admin

import (
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gaetandev/waf/internal/storage"
	"github.com/gaetandev/waf/internal/trust"
)

type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type listResponse[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
}

type VisitorInfo struct {
	IPHash          string `json:"ip_hash"`
	Domain          string `json:"domain"`
	Score           int    `json:"score"`
	State           string `json:"state"`
	FirstSeen       string `json:"first_seen"`
	LastSeen        string `json:"last_seen"`
	ReqCount        int64  `json:"req_count"`
	ViolationCount  int    `json:"violation_count"`
	ChallengePassed bool   `json:"challenge_passed"`
	CircuitOpen     bool   `json:"circuit_open"`
}

type SecurityEventSummary struct {
	Timestamp  string `json:"timestamp"`
	RequestID  string `json:"request_id,omitempty"`
	IP         string `json:"ip"`
	Domain     string `json:"domain"`
	Method     string `json:"method,omitempty"`
	Path       string `json:"path,omitempty"`
	Action     string `json:"action"`
	Reason     string `json:"reason"`
	TrustScore int    `json:"trust_score"`
}

type WAFStats struct {
	UptimeSeconds       int64 `json:"uptime_seconds"`
	TotalRequests       int64 `json:"total_requests"`
	RequestsPassed      int64 `json:"requests_passed"`
	RequestsChallenged  int64 `json:"requests_challenged"`
	RequestsBlocked     int64 `json:"requests_blocked"`
	RequestsRateLimited int64 `json:"requests_rate_limited"`
	ActiveVisitors      int   `json:"active_visitors"`
	TrustedVisitors     int   `json:"trusted_visitors"`
	MonitoredVisitors   int   `json:"monitored_visitors"`
	ChallengedVisitors  int   `json:"challenged_visitors"`
	BlockedVisitors     int   `json:"blocked_visitors"`
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /waf/health", s.health)
	mux.Handle("GET /waf/stats", s.auth(http.HandlerFunc(s.stats)))
	mux.Handle("GET /waf/admin/config", s.auth(http.HandlerFunc(s.getConfig)))
	mux.Handle("PATCH /waf/admin/config", s.auth(http.HandlerFunc(s.patchConfig)))
	mux.Handle("GET /waf/admin/whitelist", s.auth(http.HandlerFunc(s.getWhitelist)))
	mux.Handle("POST /waf/admin/whitelist", s.auth(http.HandlerFunc(s.addWhitelist)))
	mux.Handle("DELETE /waf/admin/whitelist/", s.auth(http.HandlerFunc(s.deleteWhitelist)))
	mux.Handle("GET /waf/admin/blacklist", s.auth(http.HandlerFunc(s.getBlacklist)))
	mux.Handle("POST /waf/admin/blacklist", s.auth(http.HandlerFunc(s.addBlacklist)))
	mux.Handle("DELETE /waf/admin/blacklist/", s.auth(http.HandlerFunc(s.deleteBlacklist)))
	mux.Handle("GET /waf/admin/visitors", s.auth(http.HandlerFunc(s.listVisitors)))
	mux.Handle("GET /waf/admin/visitors/", s.auth(http.HandlerFunc(s.getVisitor)))
	mux.Handle("DELETE /waf/admin/visitors/", s.auth(http.HandlerFunc(s.deleteVisitor)))
	mux.Handle("GET /waf/admin/events", s.auth(http.HandlerFunc(s.listEvents)))
	mux.Handle("GET /waf/admin/audit", s.auth(http.HandlerFunc(s.listAudit)))
	mux.Handle("POST /waf/admin/gdpr/erase", s.auth(http.HandlerFunc(s.gdprErase)))
	return mux
}

// gdprErase efface toutes les données d'un visiteur par son IP (droit à
// l'effacement, FR-28). L'IP est hashée pour retrouver l'entrée du store.
func (s *Server) gdprErase(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		IP string `json:"ip"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || payload.IP == "" {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_request", Message: "ip is required"})
		return
	}
	ipHash := trust.HashIP(payload.IP)
	_, existed := s.store.GetVisitor(ipHash)
	s.store.DeleteVisitor(ipHash)
	s.record("gdpr_erase", ipHash, "erased")
	writeJSON(w, http.StatusOK, map[string]any{"erased": existed, "ip_hash": ipHash})
}

// record journalise une action d'administration (no-op si l'audit est désactivé).
func (s *Server) record(action string, target string, result string) {
	if s.trail != nil {
		s.trail.Record(action, target, result)
	}
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	if s.trail == nil {
		writeJSON(w, http.StatusOK, listResponse[any]{Items: []any{}, Total: 0})
		return
	}
	writeJSON(w, http.StatusOK, paged(s.trail.List(), r))
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		// Anti-brute-force (FR-30) : verrouille l'IP après trop d'échecs.
		if s.brute != nil && s.brute.Limited(ip) {
			w.Header().Set("Retry-After", "300")
			writeJSON(w, http.StatusTooManyRequests, errorResponse{Error: "locked", Message: "Too many failed attempts"})
			return
		}
		expected := "Bearer " + s.cfg.Admin.Token
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(expected)) != 1 {
			if s.brute != nil {
				s.brute.Record(ip)
			}
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "unauthorized", Message: "Missing or invalid Bearer token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"version":        s.cfg.Version,
		"uptime_seconds": int64(time.Since(s.startedAt).Seconds()),
	})
}

func (s *Server) stats(w http.ResponseWriter, _ *http.Request) {
	visitors := s.store.ListVisitors()
	stats := WAFStats{
		UptimeSeconds:  int64(time.Since(s.startedAt).Seconds()),
		ActiveVisitors: len(visitors),
	}
	for _, visitor := range visitors {
		switch s.scores.State(visitor.Score) {
		case "TRUSTED":
			stats.TrustedVisitors++
		case "MONITORED":
			stats.MonitoredVisitors++
		case "CHALLENGED":
			stats.ChallengedVisitors++
		case "BLOCKED":
			stats.BlockedVisitors++
		}
		stats.TotalRequests += visitor.ReqCount
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) getConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.state.Config())
}

func (s *Server) patchConfig(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_config_update", Message: "Invalid JSON body"})
		return
	}
	updated := make([]string, 0, len(payload))
	for key := range payload {
		switch key {
		case "rate_limit", "trust", "challenge":
			updated = append(updated, key)
		default:
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_config_update", Message: "Unsupported config section"})
			return
		}
	}
	sort.Strings(updated)
	s.record("config_patch", strings.Join(updated, ","), "applied")
	writeJSON(w, http.StatusOK, map[string]any{"updated_fields": updated})
}

func (s *Server) getWhitelist(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, paged(s.state.ListWhitelist(), r))
}

func (s *Server) addWhitelist(w http.ResponseWriter, r *http.Request) {
	s.addIPEntry(w, r, true)
}

func (s *Server) deleteWhitelist(w http.ResponseWriter, r *http.Request) {
	target := pathTail(r, "/waf/admin/whitelist/")
	if !s.state.RemoveWhitelist(target) {
		http.NotFound(w, r)
		return
	}
	s.record("remove_whitelist", target, "removed")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getBlacklist(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, paged(s.state.ListBlacklist(), r))
}

func (s *Server) addBlacklist(w http.ResponseWriter, r *http.Request) {
	s.addIPEntry(w, r, false)
}

func (s *Server) deleteBlacklist(w http.ResponseWriter, r *http.Request) {
	target := pathTail(r, "/waf/admin/blacklist/")
	if !s.state.RemoveBlacklist(target) {
		http.NotFound(w, r)
		return
	}
	s.record("remove_blacklist", target, "removed")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) addIPEntry(w http.ResponseWriter, r *http.Request, whitelist bool) {
	var entry IPEntry
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entry); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_ip_entry", Message: "Invalid JSON body"})
		return
	}
	var created IPEntry
	var exists bool
	var err error
	if whitelist {
		created, exists, err = s.state.AddWhitelist(entry)
	} else {
		created, exists, err = s.state.AddBlacklist(entry)
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid_ip", Message: "IP or CIDR is invalid"})
		return
	}
	if exists {
		writeJSON(w, http.StatusConflict, errorResponse{Error: "already_exists", Message: "Entry already exists"})
		return
	}
	action := "add_blacklist"
	if whitelist {
		action = "add_whitelist"
	}
	s.record(action, entry.IP, "created")
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) listVisitors(w http.ResponseWriter, r *http.Request) {
	visitors := visitorInfos(s.store.ListVisitors(), s.scores)
	domain := r.URL.Query().Get("domain")
	state := r.URL.Query().Get("state")
	filtered := visitors[:0]
	for _, visitor := range visitors {
		if domain != "" && visitor.Domain != domain {
			continue
		}
		if state != "" && visitor.State != state {
			continue
		}
		filtered = append(filtered, visitor)
	}
	sortVisitors(filtered, r.URL.Query().Get("sort"))
	writeJSON(w, http.StatusOK, paged(filtered, r))
}

func (s *Server) getVisitor(w http.ResponseWriter, r *http.Request) {
	ipHash := pathTail(r, "/waf/admin/visitors/")
	visitor, ok := s.store.GetVisitor(ipHash)
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, visitorInfo(*visitor, s.scores))
}

func (s *Server) deleteVisitor(w http.ResponseWriter, r *http.Request) {
	ipHash := pathTail(r, "/waf/admin/visitors/")
	if _, ok := s.store.GetVisitor(ipHash); !ok {
		http.NotFound(w, r)
		return
	}
	s.store.DeleteVisitor(ipHash)
	s.record("reset_visitor", ipHash, "reset")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	events := s.state.Events()
	domain := r.URL.Query().Get("domain")
	action := r.URL.Query().Get("action")
	filtered := events[:0]
	for _, event := range events {
		if domain != "" && event.Domain != domain {
			continue
		}
		if action != "" && event.Action != action {
			continue
		}
		filtered = append(filtered, event)
	}
	writeJSON(w, http.StatusOK, paged(filtered, r))
}

func visitorInfos(visitors []storage.VisitorState, scores *trust.ScoreManager) []VisitorInfo {
	items := make([]VisitorInfo, 0, len(visitors))
	for _, visitor := range visitors {
		items = append(items, visitorInfo(visitor, scores))
	}
	return items
}

func visitorInfo(visitor storage.VisitorState, scores *trust.ScoreManager) VisitorInfo {
	return VisitorInfo{
		IPHash:          visitor.IPHash,
		Domain:          visitor.Domain,
		Score:           visitor.Score,
		State:           scores.State(visitor.Score),
		FirstSeen:       visitor.FirstSeen.UTC().Format(time.RFC3339),
		LastSeen:        visitor.LastSeen.UTC().Format(time.RFC3339),
		ReqCount:        visitor.ReqCount,
		ViolationCount:  visitor.ViolationCount,
		ChallengePassed: visitor.ChallengePassed,
		CircuitOpen:     visitor.CircuitOpen,
	}
}

func sortVisitors(visitors []VisitorInfo, sortBy string) {
	sort.Slice(visitors, func(i, j int) bool {
		switch sortBy {
		case "score_asc":
			return visitors[i].Score < visitors[j].Score
		case "score_desc":
			return visitors[i].Score > visitors[j].Score
		default:
			return visitors[i].LastSeen > visitors[j].LastSeen
		}
	})
}

func paged[T any](items []T, r *http.Request) listResponse[T] {
	total := len(items)
	page := queryInt(r, "page", 1)
	limit := queryInt(r, "limit", 50)
	if limit > 1000 {
		limit = 1000
	}
	start := (page - 1) * limit
	if start >= total {
		return listResponse[T]{Items: []T{}, Total: total}
	}
	end := start + limit
	if end > total {
		end = total
	}
	return listResponse[T]{Items: items[start:end], Total: total}
}

func queryInt(r *http.Request, name string, defaultValue int) int {
	value, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || value < 1 {
		return defaultValue
	}
	return value
}

func pathTail(r *http.Request, prefix string) string {
	escaped := strings.TrimPrefix(r.URL.EscapedPath(), prefix)
	value, err := url.PathUnescape(escaped)
	if err != nil {
		return escaped
	}
	return value
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
