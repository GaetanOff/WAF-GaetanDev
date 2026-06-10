// Package tlsmgr termine le TLS sur le WAF en présentant un certificat distinct
// par domaine, sélectionné par SNI (FR-33, ADR-017). Les certificats sont des
// paires PEM existantes sur disque, chargées au démarrage : un fichier manquant,
// illisible, ou dont la clé ne correspond pas au certificat fait échouer le
// démarrage (fail-fast). Un certificat par défaut optionnel est servi pour les
// SNI sans correspondance ; sans lui, un SNI inconnu provoque un refus de
// handshake (jamais de certificat arbitraire servi en silence).
package tlsmgr

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/gaetandev/waf/internal/config"
)

// Manager détient les certificats chargés et construit le tls.Config du serveur.
type Manager struct {
	certs        []domainCert
	defaultCert  *tls.Certificate
	minVersion   uint16
	cipherSuites []uint16
}

type domainCert struct {
	host     string // hôte normalisé (minuscule), wildcard sans le préfixe "*."
	wildcard bool
	cert     tls.Certificate
	leaf     *x509.Certificate
}

// New charge les certificats de la configuration. Retourne une erreur (fail-fast)
// au moindre problème de chargement.
func New(cfg config.Config) (*Manager, error) {
	minVersion, err := parseMinVersion(cfg.Server.TLS.MinVersion)
	if err != nil {
		return nil, err
	}
	cipherSuites, err := parseCipherSuites(cfg.Server.TLS.CipherSuites)
	if err != nil {
		return nil, err
	}

	m := &Manager{minVersion: minVersion, cipherSuites: cipherSuites}

	if cfg.Server.TLS.CertFile != "" || cfg.Server.TLS.KeyFile != "" {
		cert, err := loadPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("server.tls default certificate: %w", err)
		}
		m.defaultCert = &cert
	}

	for _, domain := range cfg.Domains {
		if domain.TLS == nil {
			continue
		}
		cert, err := loadPair(domain.TLS.CertFile, domain.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("domain %q certificate: %w", domain.Host, err)
		}
		host := strings.ToLower(domain.Host)
		wildcard := strings.HasPrefix(host, "*.")
		if wildcard {
			host = strings.TrimPrefix(host, "*.")
		}
		m.certs = append(m.certs, domainCert{
			host:     host,
			wildcard: wildcard,
			cert:     cert,
			leaf:     cert.Leaf,
		})
	}

	if len(m.certs) == 0 && m.defaultCert == nil {
		return nil, fmt.Errorf("tls enabled but no certificate configured")
	}

	return m, nil
}

// TLSConfig retourne la configuration TLS à attacher au serveur HTTPS.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     m.minVersion,
		CipherSuites:   m.cipherSuites,
		GetCertificate: m.getCertificate,
	}
}

// getCertificate sélectionne le certificat selon le SNI du ClientHello.
func (m *Manager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := normalizeHost(hello.ServerName)
	for i := range m.certs {
		if m.certs[i].matches(host) {
			return &m.certs[i].cert, nil
		}
	}
	if m.defaultCert != nil {
		return m.defaultCert, nil
	}
	// Pas de certificat par défaut : refus du handshake (alerte unrecognized_name
	// côté client). On ne sert jamais un certificat arbitraire en silence.
	return nil, fmt.Errorf("no certificate for SNI %q", hello.ServerName)
}

// Expiries retourne, par hôte de domaine, l'instant d'expiration (NotAfter) du
// certificat chargé, pour alimenter la métrique waf_tls_cert_expiry_seconds.
func (m *Manager) Expiries() map[string]time.Time {
	out := make(map[string]time.Time, len(m.certs))
	for i := range m.certs {
		if m.certs[i].leaf == nil {
			continue
		}
		host := m.certs[i].host
		if m.certs[i].wildcard {
			host = "*." + host
		}
		out[host] = m.certs[i].leaf.NotAfter
	}
	return out
}

func (d domainCert) matches(host string) bool {
	if d.wildcard {
		return host == d.host || strings.HasSuffix(host, "."+d.host)
	}
	return host == d.host
}

func loadPair(certFile string, keyFile string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	// Renseigne Leaf pour éviter un parse à chaque handshake et exposer NotAfter.
	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("parse leaf certificate: %w", err)
		}
		cert.Leaf = leaf
	}
	return cert, nil
}

func parseMinVersion(value string) (uint16, error) {
	switch value {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported server.tls.min_version %q (want 1.2 or 1.3)", value)
	}
}

func parseCipherSuites(names []string) ([]uint16, error) {
	if len(names) == 0 {
		return nil, nil // défaut sécurisé de Go
	}
	byName := make(map[string]uint16)
	for _, suite := range tls.CipherSuites() {
		byName[suite.Name] = suite.ID
	}
	ids := make([]uint16, 0, len(names))
	for _, name := range names {
		id, ok := byName[strings.ToUpper(name)]
		if !ok {
			return nil, fmt.Errorf("unknown or insecure cipher suite %q", name)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if colon := strings.IndexByte(host, ':'); colon >= 0 {
		host = host[:colon]
	}
	return host
}
