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
	if cfg.AntiDDoS.PressureLevels.CriticalMultiplier != 4 {
		t.Fatalf("expected default critical pressure multiplier 4, got %v", cfg.AntiDDoS.PressureLevels.CriticalMultiplier)
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
  pressure_levels:
    elevated_multiplier: 3
    high_multiplier: 2
    critical_multiplier: 0
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
	if !strings.Contains(err.Error(), "antiddos.pressure_levels.critical_multiplier") {
		t.Fatalf("expected antiddos.pressure_levels.critical_multiplier message, got %v", err)
	}
	if !strings.Contains(err.Error(), "antiddos.pressure_levels multipliers") {
		t.Fatalf("expected pressure level ordering message, got %v", err)
	}
	if !strings.Contains(err.Error(), "antiddos.retry_after_seconds") {
		t.Fatalf("expected antiddos.retry_after_seconds message, got %v", err)
	}
}

func TestLoadRejectsInvalidRiskEngineConfig(t *testing.T) {
	t.Setenv(envChallengeSecretKey, testSecret)
	t.Setenv(envAdminToken, testSecret)

	path := writeConfig(t, `
version: "1.0"
server:
  listen: ":8080"
upstream:
  address: "http://example.test"
risk_engine:
  profile: "aggressive"
  block_min_confidence: 1.2
  min_corroborating_families: 0
  tiers:
    observe: 25
    throttle: 45
    challenge: 40
    tarpit: 80
    block: 90
  weights:
    reputation: -1
    unknown: 1
  family_corroboration_threshold: 101
  human_credit:
    sticky_trust_ttl: "bad-duration"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() expected an error")
	}
	for _, expected := range []string{
		"risk_engine.profile",
		"risk_engine.block_min_confidence",
		"risk_engine.min_corroborating_families",
		"risk_engine.tiers must be strictly increasing",
		"risk_engine.weights.reputation",
		"risk_engine.weights.unknown",
		"risk_engine.family_corroboration_threshold",
		"risk_engine.human_credit.sticky_trust_ttl",
	} {
		if !strings.Contains(err.Error(), expected) {
			t.Fatalf("expected %q in validation error, got %v", expected, err)
		}
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

// validBaseConfig retourne une config minimale qui passe Validate(), pour
// isoler la validation d'un sous-ensemble (ici server.tls / FR-33).
func validBaseConfig() Config {
	cfg := Default()
	cfg.Version = "1.0"
	cfg.Server.Listen = ":8080"
	cfg.Upstream.Address = "http://origin:80"
	cfg.Challenge.Enabled = false
	cfg.Admin.Enabled = false
	return cfg
}

func TestValidateUnderAttack(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*UnderAttack)
		wantErr bool
	}{
		{name: "defaults are valid", mutate: func(*UnderAttack) {}, wantErr: false},
		{name: "global scope valid", mutate: func(u *UnderAttack) { u.Scope = "global" }, wantErr: false},
		{name: "invalid scope", mutate: func(u *UnderAttack) { u.Scope = "per_ip" }, wantErr: true},
		{name: "invalid trigger pressure", mutate: func(u *UnderAttack) { u.TriggerPressure = "extreme" }, wantErr: true},
		{name: "trigger normal not allowed", mutate: func(u *UnderAttack) { u.TriggerPressure = "normal" }, wantErr: true},
		{name: "exit above trigger", mutate: func(u *UnderAttack) { u.TriggerPressure = "elevated"; u.ExitPressure = "high" }, wantErr: true},
		{name: "exit equals trigger valid", mutate: func(u *UnderAttack) { u.TriggerPressure = "high"; u.ExitPressure = "high" }, wantErr: false},
		{name: "bad cooldown", mutate: func(u *UnderAttack) { u.Cooldown = "soon" }, wantErr: true},
		{name: "zero max tracked domains", mutate: func(u *UnderAttack) { u.MaxTrackedDomains = 0 }, wantErr: true},
		{name: "disabled skips validation", mutate: func(u *UnderAttack) { u.Enabled = false; u.Scope = "garbage"; u.Cooldown = "" }, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			tt.mutate(&cfg.AntiDDoS.UnderAttack)
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("Validate() expected an error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() unexpected error = %v", err)
			}
		})
	}
}

func TestValidateServerTLS(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{
			name: "valid per-domain tls",
			mutate: func(c *Config) {
				c.Server.TLS.Enabled = true
				c.Domains = []DomainConfig{{Host: "a.example.com", Upstream: "http://a", TLS: &DomainTLS{CertFile: "a.crt", KeyFile: "a.key"}}}
			},
			wantErr: false,
		},
		{
			name: "valid default cert only",
			mutate: func(c *Config) {
				c.Server.TLS.Enabled = true
				c.Server.TLS.CertFile = "def.crt"
				c.Server.TLS.KeyFile = "def.key"
			},
			wantErr: false,
		},
		{
			name: "mutually exclusive with acme",
			mutate: func(c *Config) {
				c.Server.TLS.Enabled = true
				c.Server.TLS.CertFile = "def.crt"
				c.Server.TLS.KeyFile = "def.key"
				c.ACME.Enabled = true
				c.ACME.Domains = []string{"a.example.com"}
			},
			wantErr: true,
		},
		{
			name: "no certificate source",
			mutate: func(c *Config) {
				c.Server.TLS.Enabled = true
			},
			wantErr: true,
		},
		{
			name: "domain tls missing key",
			mutate: func(c *Config) {
				c.Server.TLS.Enabled = true
				c.Domains = []DomainConfig{{Host: "a.example.com", Upstream: "http://a", TLS: &DomainTLS{CertFile: "a.crt"}}}
			},
			wantErr: true,
		},
		{
			name: "default cert missing key",
			mutate: func(c *Config) {
				c.Server.TLS.Enabled = true
				c.Server.TLS.CertFile = "def.crt"
			},
			wantErr: true,
		},
		{
			name: "invalid min version",
			mutate: func(c *Config) {
				c.Server.TLS.Enabled = true
				c.Server.TLS.MinVersion = "1.1"
				c.Server.TLS.CertFile = "def.crt"
				c.Server.TLS.KeyFile = "def.key"
			},
			wantErr: true,
		},
		{
			name:    "disabled tls is always valid",
			mutate:  func(c *Config) { c.Server.TLS.Enabled = false },
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("Validate() expected an error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() unexpected error = %v", err)
			}
		})
	}
}
