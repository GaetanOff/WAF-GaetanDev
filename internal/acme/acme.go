// Package acme gère les certificats TLS via ACME / Let's Encrypt (FR-31) en
// s'appuyant sur golang.org/x/crypto/acme/autocert. autocert renouvelle
// automatiquement les certificats ~30 jours avant expiration et sert le nouveau
// certificat à chaud (rotation transparente).
package acme

import (
	"crypto/tls"
	"net/http"

	"github.com/gaetandev/waf/internal/config"
	"golang.org/x/crypto/acme/autocert"
)

// Manager encapsule autocert.Manager configuré pour les domaines du WAF.
type Manager struct {
	mgr *autocert.Manager
}

func NewManager(cfg config.ACME) *Manager {
	cacheDir := cfg.CacheDir
	if cacheDir == "" {
		cacheDir = "./certs"
	}
	return &Manager{
		mgr: &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cacheDir),
			HostPolicy: autocert.HostWhitelist(cfg.Domains...),
			Email:      cfg.Email,
		},
	}
}

// TLSConfig retourne une configuration TLS qui obtient/renouvelle les certificats
// via ACME (tls-alpn-01 + cache). À utiliser sur le serveur HTTPS public.
func (m *Manager) TLSConfig() *tls.Config {
	cfg := m.mgr.TLSConfig()
	cfg.MinVersion = tls.VersionTLS12
	return cfg
}

// HTTPHandler sert le challenge HTTP-01 d'ACME et redirige le reste vers HTTPS
// (si fallback est nil, autocert applique une redirection 302 vers https).
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	return m.mgr.HTTPHandler(fallback)
}
