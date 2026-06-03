---
status: accepted
date: 2026-06-03
deciders: GaetanDev
---

# ADR-001 — Choix du langage : Go vs Bun/TypeScript

## Context

Le WAF doit gérer du trafic HTTP à haute fréquence (objectif > 50 000 req/s) avec une latence ajoutée inférieure à 5 ms en P99. Deux options principales ont été évaluées : Go et Bun (runtime JavaScript/TypeScript ultra-performant basé sur JavaScriptCore).

## Options Evaluées

### Option A — Go 1.22+

**Avantages :**
- Goroutines légères (~2 KB stack) : gestion native de millions de connexions concurrentes
- `net/http` et `net/http/httputil.ReverseProxy` : reverse proxy production-grade inclus dans stdlib
- Performances réseau proches du C (zero-copy avec `io.Copy`, splice syscall)
- Binaire statique unique (CGO_ENABLED=0) : déploiement trivial
- `sync.Map` et atomic ops : state management haute performance sans locks coûteux
- Gestion mémoire prévisible avec GC à faibles pauses (< 1 ms)
- Écosystème mature pour proxy HTTP : `github.com/valyala/fasthttp`, `zerolog`, `go-redis`
- `golangci-lint` + `gofmt` + `go vet` : outillage code quality robuste
- Compilation croisée triviale (GOOS=linux GOARCH=amd64/arm64)

**Inconvénients :**
- Verbosité comparée à TypeScript pour certains patterns
- Pas de génériques aussi expressifs qu'en TypeScript (Go 1.18+ améliore mais reste limité)

### Option B — Bun (TypeScript/JavaScript)

**Avantages :**
- Syntaxe TypeScript plus expressive
- Hot-reload natif en développement
- Interopérabilité native avec l'écosystème npm

**Inconvénients :**
- Performances réseau inférieures à Go pour du proxy HTTP pur (benchmarks : 2-3x moins de req/s)
- Garbage collector JavaScript moins prévisible que Go pour des workloads temps-réel
- `Bun.serve()` ne supporte pas nativement HTTP/2 upstream en proxy mode
- Gestion de la concurrence moins naturelle (event loop vs goroutines)
- Déploiement : nécessite le runtime Bun installé (pas de binaire statique natif)
- Maturité production moins éprouvée pour des composants réseau critiques
- Moins de bibliothèques cryptographiques certifiées

## Decision

**Go est choisi.**

Les raisons déterminantes :
1. **Performances** : Go offre une latence P99 2-3x inférieure à Bun pour du proxy HTTP, ce qui est critique pour respecter le NFR de < 5 ms.
2. **Concurrence native** : les goroutines Go sont le modèle de concurrence le plus adapté à un proxy réseau haute fréquence.
3. **Binaire statique** : NFR-05 exige un binaire unique déployable — Go le fournit nativement.
4. **Stdlib HTTP** : `net/http/httputil.ReverseProxy` est une implémentation éprouvée de reverse proxy, correcte pour HTTP/1.1 et HTTP/2.
5. **Maintenabilité** : le code Go est idiomatique, lisible, et le tooling (gofmt, go vet, golangci-lint) garantit une qualité constante.

## Consequences

- Le projet est développé en Go 1.22+
- Les dépendances clés : `zerolog` (logging), `prometheus/client_golang` (métriques), `go-redis/redis` (optionnel), `golang.org/x/crypto` (HMAC/hash)
- Pas de dépendances à des frameworks web lourds (Gin, Echo) — `net/http` stdlib suffit
- La spec `specific-go.mdc` du projet s'applique intégralement

## Spec References

- [requirements.md](../requirements.md) NFR-01 (Performance), NFR-05 (Déploiement)
- [architecture.md](../architecture.md) — Structure Go packages
