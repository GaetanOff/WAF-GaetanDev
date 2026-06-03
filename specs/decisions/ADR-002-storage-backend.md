---
status: accepted
date: 2026-06-03
deciders: GaetanDev
---

# ADR-002 — Backend de stockage de l'état des visiteurs

## Context

Le WAF doit maintenir un état par visiteur (score de confiance, rate buckets, nonces) avec des accès très fréquents (chaque requête). Deux approches ont été évaluées : stockage in-memory (dans le processus Go) et stockage externe (Redis).

## Options Evaluées

### Option A — In-Memory (sync.Map + LRU + TTL goroutine)

**Avantages :**
- Latence d'accès : < 100 ns (vs 100-500 µs pour Redis via réseau)
- Zéro dépendance infrastructure pour un déploiement single-node
- Contrôle total sur l'éviction (LRU) et les TTLs
- Pas de sérialisation/désérialisation JSON

**Inconvénients :**
- État perdu si le processus redémarre
- Pas partageable entre plusieurs instances WAF (pas de clustering)

### Option B — Redis

**Avantages :**
- État persistant entre redémarrages
- Multi-instances WAF possibles (clustering horizontal)
- TTL natif sur les clés

**Inconvénients :**
- Dépendance infrastructure obligatoire même pour un seul nœud
- Latence réseau ajoutée (100-500 µs) — incompatible avec NFR-01 (P99 < 5 ms)
- Risque de contention si Redis est saturé

## Decision

**In-Memory par défaut, Redis optionnel.**

Architecture retenue :
- Interface `storage.Store` abstraite (définie dans `internal/storage/interface.go`)
- Implémentation `memory.Store` : `sync.Map` avec goroutine de nettoyage TTL + éviction LRU quand la limite de taille est atteinte
- Implémentation `redis.Store` : activable via config (`storage.backend: redis`) pour les déploiements multi-instances

**Taille maximale en mémoire** : configurable (défaut 100 000 entrées visiteurs ≈ ~50 MB).

**À la limite** : éviction LRU (les visiteurs les moins récemment actifs sont supprimés en premier).

**Perte d'état au redémarrage** : acceptable pour un WAF — les visiteurs reprennent leur session via le cookie signé. Le score est recalculé si le cookie est valide.

## Consequences

- `internal/storage/interface.go` définit l'interface `Store`
- `internal/storage/memory/store.go` implémentation in-memory
- `internal/storage/redis/store.go` implémentation Redis (optionnelle)
- La config `storage.backend` sélectionne l'implémentation au démarrage
- Les tests d'intégration utilisent toujours l'implémentation memory (pas de Redis en CI)

## Spec References

- [requirements.md](../requirements.md) NFR-01 (Performance), NFR-02 (Fiabilité)
- [architecture.md](../architecture.md) — Data Model
