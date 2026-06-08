package threatintel

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"time"
)

// HTTPSource interroge une API de réputation type AbuseIPDB v2. Le lookup est
// bloquant mais exécuté dans la goroutine de résolution asynchrone du Checker
// (NFR-08), jamais sur le chemin de la requête.
type HTTPSource struct {
	client *http.Client
	url    string
	apiKey string
}

func NewHTTPSource(rawURL string, apiKey string, client *http.Client) HTTPSource {
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	return HTTPSource{client: client, url: rawURL, apiKey: apiKey}
}

type abuseResponse struct {
	Data struct {
		AbuseConfidenceScore int `json:"abuseConfidenceScore"`
	} `json:"data"`
}

// Lookup mappe le score de confiance d'abus vers un niveau (FR-13 : >= 80
// critique, >= 50 malveillant).
func (s HTTPSource) Lookup(ip net.IP) Verdict {
	endpoint, err := url.Parse(s.url)
	if err != nil {
		return Verdict{Level: LevelClean}
	}
	query := endpoint.Query()
	query.Set("ipAddress", ip.String())
	endpoint.RawQuery = query.Encode()

	request, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return Verdict{Level: LevelClean}
	}
	request.Header.Set("Accept", "application/json")
	if s.apiKey != "" {
		request.Header.Set("Key", s.apiKey)
	}

	response, err := s.client.Do(request)
	if err != nil {
		return Verdict{Level: LevelClean}
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return Verdict{Level: LevelClean}
	}

	var payload abuseResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return Verdict{Level: LevelClean}
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
