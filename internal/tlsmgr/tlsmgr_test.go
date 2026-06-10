package tlsmgr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
)

// writeCertPair génère une paire cert/clé ECDSA auto-signée pour les DNS donnés
// et l'écrit dans dir. Retourne les chemins cert/clé.
func writeCertPair(t *testing.T, dir string, name string, dnsNames ...string) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return writeCertPairWithKey(t, dir, name, priv, dnsNames...)
}

func writeCertPairWithKey(t *testing.T, dir string, name string, priv *ecdsa.PrivateKey, dnsNames ...string) (string, string) {
	t.Helper()
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func leafCN(t *testing.T, cert *tls.Certificate) string {
	t.Helper()
	if cert.Leaf == nil {
		t.Fatal("certificate has no parsed leaf")
	}
	return cert.Leaf.Subject.CommonName
}

func baseConfig(domains ...config.DomainConfig) config.Config {
	cfg := config.Default()
	cfg.Server.TLS.Enabled = true
	cfg.Domains = domains
	return cfg
}

func TestGetCertificateSelectsByExactSNI(t *testing.T) {
	dir := t.TempDir()
	alphaCert, alphaKey := writeCertPair(t, dir, "alpha", "alpha.example.com")
	betaCert, betaKey := writeCertPair(t, dir, "beta", "beta.example.com")

	mgr, err := New(baseConfig(
		config.DomainConfig{Host: "alpha.example.com", Upstream: "http://a", TLS: &config.DomainTLS{CertFile: alphaCert, KeyFile: alphaKey}},
		config.DomainConfig{Host: "beta.example.com", Upstream: "http://b", TLS: &config.DomainTLS{CertFile: betaCert, KeyFile: betaKey}},
	))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got, err := mgr.getCertificate(&tls.ClientHelloInfo{ServerName: "beta.example.com"})
	if err != nil {
		t.Fatalf("getCertificate error = %v", err)
	}
	if cn := leafCN(t, got); cn != "beta.example.com" {
		t.Fatalf("selected CN = %q, want beta.example.com", cn)
	}
}

func TestGetCertificateMatchesWildcard(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeCertPair(t, dir, "wild", "*.api.example.com")

	mgr, err := New(baseConfig(
		config.DomainConfig{Host: "*.api.example.com", Upstream: "http://a", TLS: &config.DomainTLS{CertFile: cert, KeyFile: key}},
	))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got, err := mgr.getCertificate(&tls.ClientHelloInfo{ServerName: "v1.api.example.com"})
	if err != nil {
		t.Fatalf("getCertificate error = %v", err)
	}
	if cn := leafCN(t, got); cn != "*.api.example.com" {
		t.Fatalf("selected CN = %q, want *.api.example.com", cn)
	}
}

func TestGetCertificateUnknownSNIFallsBackToDefault(t *testing.T) {
	dir := t.TempDir()
	domainCertFile, domainKey := writeCertPair(t, dir, "alpha", "alpha.example.com")
	defCert, defKey := writeCertPair(t, dir, "default", "default.example.com")

	cfg := baseConfig(
		config.DomainConfig{Host: "alpha.example.com", Upstream: "http://a", TLS: &config.DomainTLS{CertFile: domainCertFile, KeyFile: domainKey}},
	)
	cfg.Server.TLS.CertFile = defCert
	cfg.Server.TLS.KeyFile = defKey

	mgr, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got, err := mgr.getCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example.org"})
	if err != nil {
		t.Fatalf("getCertificate error = %v", err)
	}
	if cn := leafCN(t, got); cn != "default.example.com" {
		t.Fatalf("selected CN = %q, want default.example.com", cn)
	}
}

func TestGetCertificateUnknownSNIWithoutDefaultIsRejected(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeCertPair(t, dir, "alpha", "alpha.example.com")

	mgr, err := New(baseConfig(
		config.DomainConfig{Host: "alpha.example.com", Upstream: "http://a", TLS: &config.DomainTLS{CertFile: cert, KeyFile: key}},
	))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err := mgr.getCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example.org"}); err == nil {
		t.Fatal("expected handshake rejection for unknown SNI without default certificate")
	}
}

func TestNewFailsFastOnMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := New(baseConfig(
		config.DomainConfig{Host: "alpha.example.com", Upstream: "http://a", TLS: &config.DomainTLS{
			CertFile: filepath.Join(dir, "does-not-exist.crt"),
			KeyFile:  filepath.Join(dir, "does-not-exist.key"),
		}},
	))
	if err == nil {
		t.Fatal("expected New() to fail when a certificate file is missing")
	}
}

func TestNewFailsFastOnKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	// Certificat signé avec une clé A, mais on fournit la clé B (non concordante).
	keyA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certFile, _ := writeCertPairWithKey(t, dir, "mismatch", keyA, "alpha.example.com")

	keyB, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyBDER, _ := x509.MarshalECPrivateKey(keyB)
	wrongKeyPath := filepath.Join(dir, "wrong.key")
	if err := os.WriteFile(wrongKeyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBDER}), 0o600); err != nil {
		t.Fatalf("write wrong key: %v", err)
	}

	_, err := New(baseConfig(
		config.DomainConfig{Host: "alpha.example.com", Upstream: "http://a", TLS: &config.DomainTLS{CertFile: certFile, KeyFile: wrongKeyPath}},
	))
	if err == nil {
		t.Fatal("expected New() to fail when the key does not match the certificate")
	}
}

func TestExpiriesExposesNotAfterPerDomain(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeCertPair(t, dir, "alpha", "alpha.example.com")

	mgr, err := New(baseConfig(
		config.DomainConfig{Host: "alpha.example.com", Upstream: "http://a", TLS: &config.DomainTLS{CertFile: cert, KeyFile: key}},
	))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	expiries := mgr.Expiries()
	if _, ok := expiries["alpha.example.com"]; !ok {
		t.Fatalf("Expiries() missing alpha.example.com, got %v", expiries)
	}
}

func TestTLSConfigMinVersion(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeCertPair(t, dir, "alpha", "alpha.example.com")

	cfg := baseConfig(
		config.DomainConfig{Host: "alpha.example.com", Upstream: "http://a", TLS: &config.DomainTLS{CertFile: cert, KeyFile: key}},
	)
	cfg.Server.TLS.MinVersion = "1.3"

	mgr, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := mgr.TLSConfig().MinVersion; got != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %d, want %d (TLS 1.3)", got, tls.VersionTLS13)
	}
}

func TestNewRejectsUnknownCipherSuite(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeCertPair(t, dir, "alpha", "alpha.example.com")

	cfg := baseConfig(
		config.DomainConfig{Host: "alpha.example.com", Upstream: "http://a", TLS: &config.DomainTLS{CertFile: cert, KeyFile: key}},
	)
	cfg.Server.TLS.CipherSuites = []string{"TLS_NOT_A_REAL_SUITE"}

	if _, err := New(cfg); err == nil {
		t.Fatal("expected New() to reject an unknown cipher suite")
	}
}
