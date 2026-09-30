package main

import (
	"testing"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/trust"
)

// FR-28 : la clé des ip_hash dérive de challenge.secret_key. Deux instances
// qui partagent la configuration calculent les mêmes hashes (store Redis
// commun) ; un autre secret en calcule d'autres.
func TestConfigureIPHashDerivesTheKeyFromTheChallengeSecret(t *testing.T) {
	hashWith := func(secret string) string {
		cfg := config.Default()
		cfg.Challenge.SecretKey = secret
		if err := (&app{cfg: &cfg}).configureIPHash(); err != nil {
			t.Fatalf("configureIPHash() error = %v", err)
		}
		return trust.HashIP("203.0.113.7")
	}
	first := hashWith("0123456789abcdef0123456789abcdef")
	if again := hashWith("0123456789abcdef0123456789abcdef"); again != first {
		t.Fatalf("same secret: %q then %q, want equal hashes", first, again)
	}
	if other := hashWith("fedcba9876543210fedcba9876543210"); other == first {
		t.Fatal("another secret must produce another hash")
	}
}
