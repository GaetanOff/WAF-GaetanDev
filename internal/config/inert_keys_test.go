package config

import (
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
