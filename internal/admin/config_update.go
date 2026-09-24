package admin

import (
	"sort"

	"github.com/gaetandev/waf/internal/config"
)

// ConfigUpdate est le corps de PATCH /waf/admin/config (schéma ConfigUpdate de
// specs/api/admin.openapi.yaml) : seules les clés présentes sont modifiées.
type ConfigUpdate struct {
	RateLimit *RateLimitUpdate `json:"rate_limit"`
	Trust     *TrustUpdate     `json:"trust"`
	Challenge *ChallengeUpdate `json:"challenge"`
}

type RateLimitUpdate struct {
	Enabled           *bool    `json:"enabled"`
	RequestsPerSecond *float64 `json:"requests_per_second"`
	Burst             *int     `json:"burst"`
}

type TrustUpdate struct {
	ChallengeThreshold *int `json:"challenge_threshold"`
	BlockThreshold     *int `json:"block_threshold"`
}

type ChallengeUpdate struct {
	Enabled       *bool `json:"enabled"`
	PowDifficulty *int  `json:"pow_difficulty"`
}

// ConfigApplier pousse une configuration validée vers les composants runtime
// (rate limiter, score manager, challenge). Fourni par cmd/waf.
type ConfigApplier func(config.Config)

// applyTo reporte la mise à jour sur cfg et retourne les champs modifiés.
func (u ConfigUpdate) applyTo(cfg *config.Config) []string {
	var fields []string
	set := func(name string, apply func()) {
		apply()
		fields = append(fields, name)
	}
	if rl := u.RateLimit; rl != nil {
		if rl.Enabled != nil {
			set("rate_limit.enabled", func() { cfg.RateLimit.Enabled = *rl.Enabled })
		}
		if rl.RequestsPerSecond != nil {
			set("rate_limit.requests_per_second", func() { cfg.RateLimit.RequestsPerSecond = *rl.RequestsPerSecond })
		}
		if rl.Burst != nil {
			set("rate_limit.burst", func() { cfg.RateLimit.Burst = *rl.Burst })
		}
	}
	if tr := u.Trust; tr != nil {
		if tr.ChallengeThreshold != nil {
			set("trust.challenge_threshold", func() { cfg.Trust.ChallengeThreshold = *tr.ChallengeThreshold })
		}
		if tr.BlockThreshold != nil {
			set("trust.block_threshold", func() { cfg.Trust.BlockThreshold = *tr.BlockThreshold })
		}
	}
	if ch := u.Challenge; ch != nil {
		if ch.Enabled != nil {
			set("challenge.enabled", func() { cfg.Challenge.Enabled = *ch.Enabled })
		}
		if ch.PowDifficulty != nil {
			set("challenge.pow_difficulty", func() { cfg.Challenge.PowDifficulty = *ch.PowDifficulty })
		}
	}
	sort.Strings(fields)
	return fields
}
