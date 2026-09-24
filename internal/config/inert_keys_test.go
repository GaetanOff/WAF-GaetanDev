package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FR-03 — les fenêtres minute et heure du rate limiting. `0` désactive une
// fenêtre ; une limite horaire sous la limite par minute rend la fenêtre minute
// inatteignable, donc ne dit pas ce que l'opérateur croit.
func TestValidateRateLimitWindows(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*RateLimit)
		wantErr   bool
		wantField string
	}{
		{name: "defaults are valid", mutate: func(*RateLimit) {}},
		{name: "both windows disabled", mutate: func(r *RateLimit) { r.RequestsPerMinute = 0; r.RequestsPerHour = 0 }},
		{name: "minute window alone", mutate: func(r *RateLimit) { r.RequestsPerHour = 0 }},
		{name: "hour window alone", mutate: func(r *RateLimit) { r.RequestsPerMinute = 0 }},
		{name: "equal limits accepted", mutate: func(r *RateLimit) { r.RequestsPerMinute = 1000; r.RequestsPerHour = 1000 }},
		{
			name:      "negative minute rejected",
			mutate:    func(r *RateLimit) { r.RequestsPerMinute = -1 },
			wantErr:   true,
			wantField: "rate_limit.requests_per_minute",
		},
		{
			name:      "negative hour rejected",
			mutate:    func(r *RateLimit) { r.RequestsPerHour = -1 },
			wantErr:   true,
			wantField: "rate_limit.requests_per_hour",
		},
		{
			name:      "hour below minute rejected",
			mutate:    func(r *RateLimit) { r.RequestsPerMinute = 5000; r.RequestsPerHour = 1000 },
			wantErr:   true,
			wantField: "rate_limit.requests_per_hour",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			tt.mutate(&cfg.RateLimit)

			err := cfg.Validate()

			if !tt.wantErr {
				if err != nil {
					t.Fatalf("Validate() unexpected error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Validate() expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantField) {
				t.Fatalf("error = %v, want it to name %q", err, tt.wantField)
			}
		})
	}
}

// FR-02 — le rafraîchissement des plages Cloudflare. Sans `trusted`, les plages
// ne servent à rien : accepter la combinaison en silence recréerait l'option
// inerte que FR-02 v2.3.0 corrige.
func TestValidateCloudflareRangeRefresh(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*Cloudflare)
		wantErr   bool
		wantField string
	}{
		{name: "refresh disabled by default", mutate: func(*Cloudflare) {}},
		{name: "refresh enabled with a daily interval", mutate: func(c *Cloudflare) { c.AutoUpdateRanges = true }},
		{name: "one minute is the floor", mutate: func(c *Cloudflare) { c.AutoUpdateRanges = true; c.UpdateInterval = "1m" }},
		{
			name:      "refresh without trust rejected",
			mutate:    func(c *Cloudflare) { c.AutoUpdateRanges = true; c.Trusted = false },
			wantErr:   true,
			wantField: "cloudflare.auto_update_ranges",
		},
		{
			name:      "interval below the floor rejected",
			mutate:    func(c *Cloudflare) { c.AutoUpdateRanges = true; c.UpdateInterval = "5s" },
			wantErr:   true,
			wantField: "cloudflare.update_interval",
		},
		{
			name:      "unparsable interval rejected",
			mutate:    func(c *Cloudflare) { c.AutoUpdateRanges = true; c.UpdateInterval = "daily" },
			wantErr:   true,
			wantField: "cloudflare.update_interval",
		},
		{
			// Sans rafraîchissement, un intervalle court n'a aucun effet : le
			// rejeter serait un faux positif.
			name:   "short interval accepted while refresh is off",
			mutate: func(c *Cloudflare) { c.UpdateInterval = "1s" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			tt.mutate(&cfg.Cloudflare)

			err := cfg.Validate()

			if !tt.wantErr {
				if err != nil {
					t.Fatalf("Validate() unexpected error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Validate() expected an error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantField) {
				t.Fatalf("error = %v, want it to name %q", err, tt.wantField)
			}
		})
	}
}

// ADR-021 — budget par opération Redis.
func TestValidateRedisTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout string
		wantErr bool
	}{
		{name: "absent means the store default", timeout: ""},
		{name: "valid duration", timeout: "250ms"},
		{name: "unparsable rejected", timeout: "fast", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.Storage.Backend = "redis"
			cfg.Storage.Redis = &RedisConfig{Address: "redis:6379", Timeout: tt.timeout}

			err := cfg.Validate()

			if tt.wantErr && err == nil {
				t.Fatal("Validate() expected an error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() unexpected error = %v", err)
			}
			if tt.wantErr && !strings.Contains(err.Error(), "storage.redis.timeout") {
				t.Fatalf("error = %v, want it to name storage.redis.timeout", err)
			}
		})
	}
}

// FR-09 — seuls les deux formats contractualisés sont acceptés.
func TestValidateLoggingFormat(t *testing.T) {
	for _, format := range []string{"json", "pretty"} {
		t.Run(format, func(t *testing.T) {
			cfg := validBaseConfig()
			cfg.Logging.Format = format
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() unexpected error = %v", err)
			}
		})
	}

	cfg := validBaseConfig()
	cfg.Logging.Format = "logfmt"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "logging.format") {
		t.Fatalf("error = %v, want it to name logging.format", err)
	}
}

// ADR-022 — les surcharges domains[] jamais appliquées sont refusées avec un
// message qui nomme la clé et la raison, au lieu d'être acceptées en silence.
func TestLoadRejectsRemovedDomainOverrides(t *testing.T) {
	for _, key := range []string{
		"protected_paths: [\"/admin/\"]",
		"public_paths: [\"/static/\"]",
		"rate_limit_override: {requests_per_second: 20, burst: 40}",
		"trust_override: {block_threshold: 20}",
	} {
		name := strings.SplitN(key, ":", 2)[0]
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			content := "version: \"1.0\"\nserver:\n  listen: \":8080\"\nupstream:\n  address: \"http://127.0.0.1:3000\"\nchallenge:\n  enabled: false\nadmin:\n  enabled: false\ndomains:\n  - host: example.com\n    upstream: \"http://10.0.0.1\"\n    " + key + "\n"
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			_, err := Load(path)

			want := "domains[0]." + name + " is not supported"
			if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "ADR-022") {
				t.Fatalf("Load() error = %v, want it to contain %q and ADR-022", err, want)
			}
		})
	}
}

// FR-25 — un pool activé avec ses seuls upstreams reçoit les défauts de sonde
// documentés, au lieu d'échouer au démarrage sur health_check.interval.
func TestLoadAppliesDocumentedUpstreamPoolDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := "version: \"1.0\"\nserver:\n  listen: \":8080\"\nupstream:\n  address: \"http://127.0.0.1:3000\"\nchallenge:\n  enabled: false\nadmin:\n  enabled: false\nupstream_pool:\n  enabled: true\n  upstreams:\n    - address: \"http://10.0.0.1:80\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	want := UpstreamHealthCheck{Path: "/healthz", Interval: "10s", Timeout: "2s", HealthyThreshold: 2, UnhealthyThreshold: 3}
	if cfg.UpstreamPool.HealthCheck != want || cfg.UpstreamPool.Strategy != "round_robin" {
		t.Fatalf("upstream_pool = %+v, want the documented defaults %+v", cfg.UpstreamPool, want)
	}
}
