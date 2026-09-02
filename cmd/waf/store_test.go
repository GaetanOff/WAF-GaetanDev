package main

import (
	"strings"
	"testing"

	"github.com/gaetandev/waf/internal/config"
	wafmetrics "github.com/gaetandev/waf/internal/metrics"
	"github.com/gaetandev/waf/internal/storage/memory"
)

func TestNewStoreDefaultsToMemory(t *testing.T) {
	cfg := config.Default()

	store, err := newStore(cfg, wafmetrics.New())
	if err != nil {
		t.Fatalf("newStore() error = %v", err)
	}
	t.Cleanup(store.Close)

	if _, ok := store.(*memory.Store); !ok {
		t.Fatalf("store = %T, want *memory.Store for the default backend", store)
	}
}

// `storage.backend: redis` doit réellement sélectionner le backend Redis. Le
// test le constate par l'échec de connexion : jusqu'à la phase 15, la clé était
// ignorée et cette configuration démarrait silencieusement en mémoire.
func TestNewStoreSelectsRedisAndFailsFastWhenUnreachable(t *testing.T) {
	cfg := config.Default()
	cfg.Storage.Backend = "redis"
	cfg.Storage.Redis = &config.RedisConfig{Address: "127.0.0.1:1", Timeout: "50ms"}

	store, err := newStore(cfg, wafmetrics.New())
	if err == nil {
		store.Close()
		t.Fatal("newStore() error = nil, want a startup failure on an unreachable Redis")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("error = %v, want it to name the configured Redis address", err)
	}
}

func TestNewStoreRejectsRedisBackendWithoutRedisBlock(t *testing.T) {
	cfg := config.Default()
	cfg.Storage.Backend = "redis"
	cfg.Storage.Redis = nil

	store, err := newStore(cfg, wafmetrics.New())
	if err == nil {
		store.Close()
		t.Fatal("newStore() error = nil, want a failure when storage.redis is missing")
	}
	if !strings.Contains(err.Error(), "storage.redis") {
		t.Fatalf("error = %v, want it to name storage.redis", err)
	}
}
