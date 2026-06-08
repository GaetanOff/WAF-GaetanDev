package acme

import (
	"net/http"
	"testing"

	"github.com/gaetandev/waf/internal/config"
)

func TestNewManagerBuildsTLSConfig(t *testing.T) {
	mgr := NewManager(config.ACME{
		Enabled:  true,
		Domains:  []string{"example.com"},
		Email:    "ops@example.com",
		CacheDir: t.TempDir(),
	})
	tlsCfg := mgr.TLSConfig()
	if tlsCfg == nil {
		t.Fatal("TLSConfig() returned nil")
	}
	if tlsCfg.GetCertificate == nil {
		t.Fatal("TLSConfig must provide GetCertificate (autocert)")
	}
	if tlsCfg.MinVersion == 0 {
		t.Fatal("TLSConfig must set a minimum TLS version")
	}
}

func TestHTTPHandlerNotNil(t *testing.T) {
	mgr := NewManager(config.ACME{Domains: []string{"example.com"}, CacheDir: t.TempDir()})
	if mgr.HTTPHandler(nil) == nil {
		t.Fatal("HTTPHandler returned nil")
	}
}

func TestDefaultCacheDirApplied(t *testing.T) {
	// CacheDir vide → un répertoire par défaut est utilisé (pas de panic).
	mgr := NewManager(config.ACME{Domains: []string{"example.com"}})
	if h := mgr.HTTPHandler(http.NotFoundHandler()); h == nil {
		t.Fatal("manager not usable with default cache dir")
	}
}
