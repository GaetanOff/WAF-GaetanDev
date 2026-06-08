package tlsfp

import (
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/middleware/cloudflare"
	"github.com/gaetandev/waf/internal/trust"
)

const (
	headerRiskTLS              = "X-WAF-Risk-tls"
	headerReason               = "X-WAF-Reason"
	headerDeterministicTrigger = "X-WAF-Deterministic-Trigger"
	triggerJA3Blacklist        = "ja3_blacklist"

	defaultSwapContribution = 50
)

// Middleware lit le hash JA3 (header Cloudflare), applique la blacklist JA3
// (trigger déterministe) et détecte les changements de JA3 pour un même
// visiteur entre sessions (swap = suspect → contribution `tls`).
type Middleware struct {
	enabled          bool
	header           string
	blacklist        map[string]struct{}
	swapContribution int

	mu      sync.Mutex
	lastJA3 map[string]string
}

func NewMiddleware(cfg config.TLSFingerprint) *Middleware {
	header := cfg.JA3Header
	if header == "" {
		header = "Cf-Bot-Management-Ja3Hash"
	}
	contribution := cfg.SwapContribution
	if contribution <= 0 {
		contribution = defaultSwapContribution
	}
	blacklist := make(map[string]struct{}, len(cfg.JA3Blacklist))
	for _, h := range cfg.JA3Blacklist {
		blacklist[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	return &Middleware{
		enabled:          cfg.Enabled,
		header:           header,
		blacklist:        blacklist,
		swapContribution: contribution,
		lastJA3:          make(map[string]string),
	}
}

func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.enabled || r.Header.Get("X-WAF-Action") == "PASS" {
			next.ServeHTTP(w, r)
			return
		}

		ja3 := strings.ToLower(strings.TrimSpace(r.Header.Get(m.header)))
		if ja3 == "" {
			// Pas de JA3 disponible (ex : Cloudflare sans Bot Management) →
			// collecte désactivée gracieusement (FR-11).
			next.ServeHTTP(w, r)
			return
		}

		if _, blocked := m.blacklist[ja3]; blocked {
			r.Header.Set(headerDeterministicTrigger, triggerJA3Blacklist)
			if r.Header.Get(headerReason) == "" {
				r.Header.Set(headerReason, "ja3_blacklisted")
			}
			next.ServeHTTP(w, r)
			return
		}

		if m.detectSwap(cloudflare.RealIP(r), ja3) {
			r.Header.Set(headerRiskTLS, strconv.Itoa(m.swapContribution))
			if r.Header.Get(headerReason) == "" {
				r.Header.Set(headerReason, "ja3_swap")
			}
		}

		next.ServeHTTP(w, r)
	})
}

// detectSwap retourne true si le JA3 du visiteur a changé depuis la dernière
// session observée (signe d'usurpation / outil tournant).
func (m *Middleware) detectSwap(ip string, ja3 string) bool {
	ipHash := trust.HashIP(ip)
	m.mu.Lock()
	defer m.mu.Unlock()
	previous, seen := m.lastJA3[ipHash]
	m.lastJA3[ipHash] = ja3
	return seen && previous != ja3
}
