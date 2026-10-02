// Package tlsmgr termine le TLS sur le WAF en présentant un certificat distinct
// par domaine, sélectionné par SNI (FR-40, ADR-017). Les certificats sont des
// paires PEM existantes sur disque, chargées au démarrage : un fichier manquant,
// illisible, ou dont la clé ne correspond pas au certificat fait échouer le
// démarrage (fail-fast). Un certificat par défaut optionnel est servi pour les
// SNI sans correspondance ; sans lui, un SNI inconnu provoque un refus de
// handshake (jamais de certificat arbitraire servi en silence).
//
// Une paire renouvelée sur disque est rechargée sans redémarrage (Reload,
// Watch) ; une paire invalide au rechargement laisse le certificat en service.
package tlsmgr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/hostname"
)

// ReloadInterval est la période d'examen des fichiers de certificats (FR-40).
const ReloadInterval = time.Minute

// Manager détient les certificats chargés et construit le tls.Config du serveur.
type Manager struct {
	// mu sérialise les rechargements ; les handshakes lisent state sans verrou.
	mu           sync.Mutex
	pairs        []*pair
	state        atomic.Pointer[certState]
	minVersion   uint16
	cipherSuites []uint16
}

// pair est une paire cert/clé de la configuration et sa dernière version
// chargée avec succès.
type pair struct {
	certFile, keyFile string
	host              string // hôte normalisé (minuscule), wildcard sans le préfixe "*."
	wildcard          bool
	isDefault         bool
	cert              tls.Certificate
	modTime           time.Time // dates de modification combinées à ce chargement
}

// certState est l'index de sélection, remplacé d'un bloc à chaque rechargement.
type certState struct {
	// exact et wildcard indexent les certificats par hôte (wildcard : suffixe
	// sans "*."), pour une sélection en O(labels du SNI) au handshake.
	exact       map[string]*tls.Certificate
	wildcard    map[string]*tls.Certificate
	defaultCert *tls.Certificate
	expiries    map[string]time.Time
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
		p := &pair{certFile: cfg.Server.TLS.CertFile, keyFile: cfg.Server.TLS.KeyFile, isDefault: true}
		if err := p.load(); err != nil {
			return nil, fmt.Errorf("server.tls default certificate: %w", err)
		}
		m.pairs = append(m.pairs, p)
	}

	for _, domain := range cfg.Domains {
		if domain.TLS == nil {
			continue
		}
		host := strings.ToLower(domain.Host)
		wildcard := strings.HasPrefix(host, "*.")
		if wildcard {
			host = strings.TrimPrefix(host, "*.")
		}
		p := &pair{certFile: domain.TLS.CertFile, keyFile: domain.TLS.KeyFile, host: host, wildcard: wildcard}
		if err := p.load(); err != nil {
			return nil, fmt.Errorf("domain %q certificate: %w", domain.Host, err)
		}
		m.pairs = append(m.pairs, p)
	}

	if len(m.pairs) == 0 {
		return nil, fmt.Errorf("tls enabled but no certificate configured")
	}
	m.state.Store(m.index())

	return m, nil
}

// load charge la paire et retient la date de modification de ses fichiers ;
// en cas d'erreur, la version précédente reste en place.
func (p *pair) load() error {
	modTime, err := latestModTime(p.certFile, p.keyFile)
	if err != nil {
		return err
	}
	cert, err := loadPair(p.certFile, p.keyFile)
	if err != nil {
		return err
	}
	p.cert = cert
	p.modTime = modTime
	return nil
}

// changed : un fichier de la paire a été modifié depuis le dernier
// chargement réussi.
func (p *pair) changed() (bool, error) {
	modTime, err := latestModTime(p.certFile, p.keyFile)
	if err != nil {
		return false, err
	}
	return !modTime.Equal(p.modTime), nil
}

// latestModTime rend la plus récente des dates de modification des fichiers,
// liens symboliques suivis (le live/ de certbot pointe vers archive/).
func latestModTime(files ...string) (time.Time, error) {
	var latest time.Time
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			return time.Time{}, err
		}
		if info.ModTime().After(latest) {
			latest = info.ModTime()
		}
	}
	return latest, nil
}

// index construit les tables de sélection depuis les paires. À hôte
// dupliqué, le premier déclaré gagne, comme le faisait le parcours linéaire.
func (m *Manager) index() *certState {
	state := &certState{
		exact:    make(map[string]*tls.Certificate, len(m.pairs)),
		wildcard: make(map[string]*tls.Certificate),
		expiries: make(map[string]time.Time, len(m.pairs)),
	}
	for _, p := range m.pairs {
		cert := p.cert
		if p.isDefault {
			state.defaultCert = &cert
			continue
		}
		table := state.exact
		if p.wildcard {
			table = state.wildcard
		}
		if _, taken := table[p.host]; !taken {
			table[p.host] = &cert
		}
		if cert.Leaf != nil {
			host := p.host
			if p.wildcard {
				host = "*." + host
			}
			state.expiries[host] = cert.Leaf.NotAfter
		}
	}
	return state
}

// Reload recharge les paires modifiées sur disque depuis leur dernier
// chargement réussi. Une paire invalide (écriture en cours, clé non
// concordante, fichier absent) garde son certificat en service et sera
// retentée ; son erreur est rendue. reloaded indique qu'au moins une paire a
// été remplacée.
func (m *Manager) Reload() (reloaded bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var failures []error
	for _, p := range m.pairs {
		changed, statErr := p.changed()
		if statErr != nil {
			failures = append(failures, fmt.Errorf("%s: %w", p.certFile, statErr))
			continue
		}
		if !changed {
			continue
		}
		if loadErr := p.load(); loadErr != nil {
			failures = append(failures, fmt.Errorf("%s: %w", p.certFile, loadErr))
			continue
		}
		reloaded = true
	}
	if reloaded {
		m.state.Store(m.index())
	}
	return reloaded, errors.Join(failures...)
}

// Watch appelle Reload toutes les interval jusqu'à l'annulation de ctx.
// onReload reçoit les expirations après un rechargement, onError l'échec d'un
// tour (le certificat en service est conservé).
func (m *Manager) Watch(ctx context.Context, interval time.Duration, onReload func(map[string]time.Time), onError func(error)) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				reloaded, err := m.Reload()
				if err != nil {
					onError(err)
				}
				if reloaded {
					onReload(m.Expiries())
				}
			}
		}
	}()
}

// TLSConfig retourne la configuration TLS à attacher au serveur HTTPS.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     m.minVersion,
		CipherSuites:   m.cipherSuites,
		GetCertificate: m.getCertificate,
	}
}

// getCertificate sélectionne le certificat selon le SNI du ClientHello : un
// hôte exact d'abord, puis le wildcard le plus spécifique (l'hôte lui-même, puis
// chaque domaine parent). Le parcours linéaire précédent retenait la première
// entrée déclarée qui correspondait : un "*.example.com" listé avant
// "api.example.com" lui prenait son SNI.
func (m *Manager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	state := m.state.Load()
	host := hostname.Normalize(hello.ServerName)
	if cert, ok := state.exact[host]; ok {
		return cert, nil
	}
	for suffix := host; suffix != ""; {
		if cert, ok := state.wildcard[suffix]; ok {
			return cert, nil
		}
		_, parent, found := strings.Cut(suffix, ".")
		if !found {
			break
		}
		suffix = parent
	}
	if state.defaultCert != nil {
		return state.defaultCert, nil
	}
	// Pas de certificat par défaut : refus du handshake (alerte unrecognized_name
	// côté client). On ne sert jamais un certificat arbitraire en silence.
	return nil, fmt.Errorf("no certificate for SNI %q", hello.ServerName)
}

// Expiries retourne, par hôte de domaine, l'instant d'expiration (NotAfter) du
// certificat en service, pour alimenter la métrique waf_tls_cert_expiry_seconds.
func (m *Manager) Expiries() map[string]time.Time {
	expiries := m.state.Load().expiries
	out := make(map[string]time.Time, len(expiries))
	for host, notAfter := range expiries {
		out[host] = notAfter
	}
	return out
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
