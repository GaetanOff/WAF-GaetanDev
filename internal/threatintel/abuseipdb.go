package threatintel

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/gaetandev/waf/internal/httpbody"
)

const (
	// defaultQuotaPause suspend les appels après un 429 sans Retry-After
	// exploitable ; maxQuotaPause borne un Retry-After (FR-13).
	defaultQuotaPause = time.Hour
	maxQuotaPause     = 24 * time.Hour
)

// HTTPSource interroge une API de réputation type AbuseIPDB v2. Le lookup est
// bloquant mais exécuté dans la goroutine de résolution asynchrone du Checker
// (NFR-08), jamais sur le chemin de la requête.
type HTTPSource struct {
	client *http.Client
	url    string
	apiKey string
	now    func() time.Time
	// pausedUntil (Unix nanosecondes) suspend les appels après un 429 : un
	// flood distribué épuisait le quota, et chaque IP neuve interrogeait
	// encore l'API pour recevoir un 429.
	pausedUntil atomic.Int64
}

func NewHTTPSource(rawURL string, apiKey string, client *http.Client) *HTTPSource {
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	return &HTTPSource{client: client, url: rawURL, apiKey: apiKey, now: time.Now}
}

type abuseResponse struct {
	Data struct {
		AbuseConfidenceScore int `json:"abuseConfidenceScore"`
	} `json:"data"`
}

// unavailable est le verdict d'une source qui n'a pas pu se prononcer : propre,
// mais mis en cache brièvement (Checker.store).
var unavailable = Verdict{Level: LevelClean, Unavailable: true}

// Lookup mappe le score de confiance d'abus vers un niveau (FR-13 : >= 80
// critique, >= 50 malveillant).
func (s *HTTPSource) Lookup(ip net.IP) Verdict {
	if s.now().UnixNano() < s.pausedUntil.Load() {
		return unavailable
	}
	endpoint, err := url.Parse(s.url)
	if err != nil {
		return unavailable
	}
	query := endpoint.Query()
	query.Set("ipAddress", ip.String())
	endpoint.RawQuery = query.Encode()

	request, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return unavailable
	}
	request.Header.Set("Accept", "application/json")
	if s.apiKey != "" {
		request.Header.Set("Key", s.apiKey)
	}

	response, err := s.client.Do(request)
	if err != nil {
		return unavailable
	}
	defer func() {
		httpbody.Drain(response.Body)
		_ = response.Body.Close()
	}()
	if response.StatusCode == http.StatusTooManyRequests {
		s.pause(response.Header.Get("Retry-After"))
		return unavailable
	}
	if response.StatusCode != http.StatusOK {
		return unavailable
	}

	var payload abuseResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return unavailable
	}

	switch {
	case payload.Data.AbuseConfidenceScore >= 80:
		return Verdict{Level: LevelCritical, Reason: "abuseipdb_critical"}
	case payload.Data.AbuseConfidenceScore >= 50:
		return Verdict{Level: LevelMalicious, Reason: "abuseipdb_malicious"}
	default:
		return Verdict{Level: LevelClean}
	}
}

// pause suspend les appels pendant le Retry-After (secondes) d'un 429, borné
// à maxQuotaPause ; defaultQuotaPause sans valeur exploitable.
func (s *HTTPSource) pause(retryAfter string) {
	delay := defaultQuotaPause
	if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
		delay = min(time.Duration(seconds)*time.Second, maxQuotaPause)
	}
	s.pausedUntil.Store(s.now().Add(delay).UnixNano())
}
