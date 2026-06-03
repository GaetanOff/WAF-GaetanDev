---
status: accepted
date: 2026-06-03
deciders: GaetanDev
---

# ADR-012 — Upstream Health Checks & Load Balancing

## Context

En production, un upstream peut tomber. Sans health check, le WAF continue de proxifier vers un upstream mort, générant des 502 pour tous les visiteurs. Sans failover, il n'y a aucune continuité de service.

## Health Check — Design

**Active health check** (le WAF interroge l'upstream périodiquement) plutôt que passive (observation des erreurs) car :
- Détection proactive (avant que les visiteurs voient une erreur)
- Fonctionne même si le trafic est faible

**Implémentation** : goroutine par upstream, tick configurable.

```go
type HealthChecker struct {
    upstream    *Upstream
    interval    time.Duration
    timeout     time.Duration
    path        string
    successReq  int  // succès requis pour UP
    failureReq  int  // échecs requis pour DOWN
    consecutive int  // compteur courant
    healthy     atomic.Bool
    client      *http.Client
}

func (h *HealthChecker) run(ctx context.Context) {
    ticker := time.NewTicker(h.interval)
    for {
        select {
        case <-ticker.C:
            h.check()
        case <-ctx.Done():
            return
        }
    }
}
```

L'état `healthy` est un `atomic.Bool` — accès lock-free depuis le pool de proxy goroutines.

## Load Balancing — Stratégies

### Round Robin (défaut)
Compteur atomique partagé entre toutes les goroutines :
```go
idx := atomic.AddUint64(&pool.counter, 1) % uint64(len(pool.healthy()))
```
O(1), pas de contention.

### Least Connections
Chaque upstream maintient un `atomic.Int64` des connexions actives. Sélection par `min()`. O(N) sur N upstreams, acceptable pour N ≤ 20.

### IP Hash (Sticky Sessions)
```go
hash := fnv.New32a()
hash.Write([]byte(clientIP))
idx := hash.Sum32() % uint32(len(pool.healthy()))
```
Même IP → même upstream (si sain). Si upstream tombe → redistribution cohérente.

### Poids (Weight)
Round Robin pondéré : un upstream avec `weight: 3` reçoit 3× plus de trafic.

## Failover Logic

```
Pool = [upstream-A (healthy), upstream-B (healthy), upstream-C (backup, standby)]

Cas 1 : upstream-A down
→ Retirer du pool actif
→ Requêtes routées vers upstream-B uniquement
→ Alert webhook "upstream_down"

Cas 2 : upstream-A ET upstream-B down
→ Activer upstream-C (backup)
→ Alert webhook "upstream_down_all_primary"

Cas 3 : tous down
→ HTTP 503 + page maintenance (FR-32)
→ Alert webhook critique
```

**Upstream de secours (`backup: true`)** : en standby, activé seulement si aucun upstream primaire n'est disponible.

## Retry Policy

En cas d'erreur réseau lors du proxying (pas de timeout de health check) :
- Retry 1 fois sur un upstream différent du pool
- Si retry aussi échoue → 502 au client
- Retry uniquement pour méthodes idempotentes (GET, HEAD, OPTIONS)
- Pas de retry pour POST/PUT/PATCH (risque de double soumission)

## Conséquences

- `internal/proxy/pool.go` : `UpstreamPool`, sélection selon stratégie
- `internal/proxy/health.go` : `HealthChecker`, goroutine par upstream
- `internal/proxy/handler.go` : utilise pool au lieu d'upstream unique
- Config : `upstream` devient `upstreams: []UpstreamConfig` (avec rétrocompatibilité pour config single-upstream)
- `GET /waf/admin/upstreams` : état santé de chaque upstream
- Métriques : `waf_upstream_health{upstream,domain}`, `waf_upstream_requests_total{upstream}`, `waf_upstream_latency_seconds{upstream}`
- Breaking change mineur : la clé `upstream` (singulier) reste valide (auto-converted en pool d'un seul élément)

## Spec References

- [requirements-ops.md](../requirements-ops.md) FR-25, FR-26
- [features/upstream-health.feature](../features/upstream-health.feature)
- [schemas/upstream-pool.schema.json](../schemas/upstream-pool.schema.json)
