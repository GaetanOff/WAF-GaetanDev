package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func TestLoadValidConfigWithEnvOverrides(t *testing.T) {
	t.Setenv(envChallengeSecretKey, testSecret)
	t.Setenv(envAdminToken, testSecret)

	path := writeConfig(t, `
version: "1.0"
server:
  listen: ":8080"
upstream:
  address: "http://example.test"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Challenge.SecretKey != testSecret {
		t.Fatalf("challenge secret override was not applied")
	}
	if cfg.Admin.Token != testSecret {
		t.Fatalf("admin token override was not applied")
	}
	if cfg.RateLimit.Burst != 100 {
		t.Fatalf("expected default burst 100, got %d", cfg.RateLimit.Burst)
	}
	if cfg.AntiDDoS.GlobalRequestsPerSecond != 50000 {
		t.Fatalf("expected default global threshold 50000, got %d", cfg.AntiDDoS.GlobalRequestsPerSecond)
	}
}

func TestLoadExampleConfig(t *testing.T) {
	t.Setenv(envChallengeSecretKey, testSecret)
	t.Setenv(envAdminToken, testSecret)

	cfg, err := Load(filepath.Join("..", "..", "configs", "config.example.yaml"))
	if err != nil {
		t.Fatalf("Load() example config error = %v", err)
	}

	if cfg.Server.Listen != ":8080" {
		t.Fatalf("expected example listen :8080, got %q", cfg.Server.Listen)
	}
	if len(cfg.Domains) != 3 {
		t.Fatalf("expected 3 example domains, got %d", len(cfg.Domains))
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatal("Load() expected an error")
	}
	if !strings.Contains(err.Error(), "read config") {
		t.Fatalf("expected read config error, got %v", err)
	}
}

func TestLoadRejectsMissingChallengeSecret(t *testing.T) {
	t.Setenv(envAdminToken, testSecret)

	path := writeConfig(t, `
version: "1.0"
server:
  listen: ":8080"
upstream:
  address: "http://example.test"
challenge:
  enabled: true
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() expected an error")
	}
	if !IsValidationError(err) {
		t.Fatalf("expected validation error, got %T", err)
	}
	if !strings.Contains(err.Error(), "challenge.secret_key") {
		t.Fatalf("expected challenge.secret_key message, got %v", err)
	}
}

func TestLoadRejectsInvalidFields(t *testing.T) {
	t.Setenv(envChallengeSecretKey, testSecret)
	t.Setenv(envAdminToken, testSecret)

	path := writeConfig(t, `
version: "1.0"
server:
  listen: ":8080"
upstream:
  address: "not-a-url"
rate_limit:
  burst: 0
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() expected an error")
	}

	var validationError ValidationError
	if !errors.As(err, &validationError) {
		t.Fatalf("expected ValidationError, got %T", err)
	}
	if len(validationError.Fields) < 2 {
		t.Fatalf("expected multiple field errors, got %v", validationError.Fields)
	}
}

func TestLoadRejectsInvalidAntiDDoSConfig(t *testing.T) {
	t.Setenv(envChallengeSecretKey, testSecret)
	t.Setenv(envAdminToken, testSecret)

	path := writeConfig(t, `
version: "1.0"
server:
  listen: ":8080"
upstream:
  address: "http://example.test"
antiddos:
  global_requests_per_second: 0
  global_window: "not-a-duration"
  retry_after_seconds: 0
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() expected an error")
	}
	if !strings.Contains(err.Error(), "antiddos.global_requests_per_second") {
		t.Fatalf("expected antiddos.global_requests_per_second message, got %v", err)
	}
	if !strings.Contains(err.Error(), "antiddos.global_window") {
		t.Fatalf("expected antiddos.global_window message, got %v", err)
	}
	if !strings.Contains(err.Error(), "antiddos.retry_after_seconds") {
		t.Fatalf("expected antiddos.retry_after_seconds message, got %v", err)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	t.Setenv(envChallengeSecretKey, testSecret)
	t.Setenv(envAdminToken, testSecret)

	path := writeConfig(t, `
version: "1.0"
server:
  listen: ":8080"
upstream:
  address: "http://example.test"
unknown_field: true
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() expected an error")
	}
	if !strings.Contains(err.Error(), "field unknown_field not found") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return path
}
