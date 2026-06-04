---
status: draft
version: 1.0.0
last-reviewed: 2026-06-03
---

# Validation Report — WAF Anti-DDoS / Anti-Bot

> Ce fichier est mis à jour à chaque gate check avant merge/release.

## Gate Check Log

| Date | Scope | Command | Status | Notes |
|------|-------|---------|--------|-------|
| 2026-06-04 | Slice 1.1 | `go test ./...` | pass | `cmd/waf` has no test files yet |
| 2026-06-04 | Slice 1.1 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 1.1 | `go build -o waf ./cmd/waf` | pass | Build artifact ignored by `.gitignore` |
| 2026-06-04 | Slice 1.1 | `go build -o waf.exe ./cmd/waf` + `/waf/health` | pass | Local health response: `{"status":"ok"}` |
| 2026-06-04 | Slice 1.1 | `make build` / `make test` | not run | `make` is not available in local PATH |
| 2026-06-04 | Slice 1.2 | `go mod tidy` | pass | Added `gopkg.in/yaml.v3` checksum |
| 2026-06-04 | Slice 1.2 | `go test ./...` | pass | Includes config loader, validation, env overrides, unknown field rejection |
| 2026-06-04 | Slice 1.2 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 1.2 | `go build -o waf ./cmd/waf` | pass | Config validation wired at startup |
| 2026-06-04 | Slice 1.2 | `waf.exe -config configs/config.example.yaml -listen 127.0.0.1:18081` + `/waf/health` | pass | Secrets supplied through env vars |
| 2026-06-04 | Slice 1.3 | `go test ./...` | pass | Includes proxy routing, headers, timeout config, and 502 upstream-down tests |
| 2026-06-04 | Slice 1.3 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 1.3 | `go build -o waf ./cmd/waf` | pass | Reverse proxy wired into main router |
| 2026-06-04 | Slice 1.3 | Runtime local proxy request | pass | Upstream received `X-Forwarded-For=127.0.0.1`, `X-Real-IP=127.0.0.1`, `X-WAF-Score=50` |
| 2026-06-04 | Slice 1.4 | Cloudflare IP range verification | pass | Ranges checked against official `https://www.cloudflare.com/ips-v4` and `https://www.cloudflare.com/ips-v6` |
| 2026-06-04 | Slice 1.4 | `go test ./...` | pass | Includes CF source extraction, forged header rejection, no-header fallback, IPv6 range coverage |
| 2026-06-04 | Slice 1.4 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 1.4 | `go build -o waf ./cmd/waf` | pass | Cloudflare middleware wired before proxy when `cloudflare.trusted=true` |
| 2026-06-04 | Slice 1.4 | Runtime forged `CF-Connecting-IP` request | pass | Local non-CF source returned HTTP 400 |
| 2026-06-04 | Slice 1.5 | `go test ./...` | pass | Includes memory store TTL/LRU, IP exact/CIDR lists, UA regex, whitelist priority, hot rule update |
| 2026-06-04 | Slice 1.5 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 1.5 | `go build -o waf ./cmd/waf` | pass | Access middleware wired after Cloudflare extraction and before proxy |
| 2026-06-04 | Slice 1.5 | Runtime blacklist request | pass | Local `127.0.0.1` blacklist returned HTTP 403 |
| 2026-06-04 | Slice 1.6 | `go test ./...` | pass | Includes token bucket burst/refill, 100 OK + 50 429 scenario, score -10, whitelist bypass |
| 2026-06-04 | Slice 1.6 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 1.6 | `go build -o waf ./cmd/waf` | pass | Rate limit middleware wired before proxy and after whitelist/blacklist |
| 2026-06-04 | Slice 1.6 | Runtime rate limit request | pass | `burst=1`: first request 200, second request 429 with `Retry-After=1` |
| 2026-06-04 | Slice 2.1 | `go test ./...` | pass | Includes score init, state transitions, delta clamp, TTL reset, trust middleware block/challenge markers |
| 2026-06-04 | Slice 2.1 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 2.1 | `go build -o waf ./cmd/waf` | pass | TrustScore middleware wired after rate limit and before proxy |
| 2026-06-04 | Slice 2.1 | Runtime low-score rate-limit request | pass | `initial_score=12`: first request 200, second request 403 reason `score_below_block_threshold` |

## Quality Gates Checklist

### G1 — Spec Lint
```bash
spectral lint specs/api/admin.openapi.yaml --ruleset .spectral.yaml
```
| Check | Status | Notes |
|-------|--------|-------|
| OpenAPI 3.1 valide | ⬜ | |
| Tous les operationId uniques | ⬜ | |
| Tous les schemas avec additionalProperties: false | ⬜ | |
| Pas de $ref cassés | ⬜ | |

### G2 — Type Check
```bash
go vet ./...
golangci-lint run
```
| Check | Status | Notes |
|-------|--------|-------|
| `go vet` sans erreur | ⬜ | |
| `golangci-lint` sans erreur | ⬜ | |
| Pas de `any` type non justifié | ⬜ | |
| Pas de `panic` non récupéré | ⬜ | |

### G3 — API Conformance
```bash
go test ./... -run TestAPI -v
```
| Endpoint | Status | Notes |
|----------|--------|-------|
| GET /waf/health | ⬜ | |
| POST /waf/verify — success flow | ⬜ | |
| POST /waf/verify — token expiré | ⬜ | |
| POST /waf/verify — PoW invalide | ⬜ | |
| POST /waf/admin/whitelist | ⬜ | |
| DELETE /waf/admin/whitelist/{ip} | ⬜ | |
| POST /waf/admin/blacklist | ⬜ | |
| GET /waf/admin/visitors | ⬜ | |
| GET /waf/admin/events | ⬜ | |
| GET /waf/stats | ⬜ | |
| Auth invalide → 401 | ⬜ | |

### G4 — Behavior Tests (Gherkin)
```bash
go test ./... -run TestBehavior -v
```
| Feature | Scénarios | Passed | Status |
|---------|-----------|--------|--------|
| anti-ddos.feature | 7 | ⬜ | ⬜ |
| anti-bot.feature | 10 | ⬜ | ⬜ |
| js-challenge.feature | 13 | ⬜ | ⬜ |
| whitelist-blacklist.feature | 11 | ⬜ | ⬜ |
| trust-score.feature | 11 | ⬜ | ⬜ |

### G5 — Security
```bash
go list -json -m all | nancy sleuth
govulncheck ./...
```
| Check | Status | Notes |
|-------|--------|-------|
| Pas de CVE critiques dans les dépendances | ⬜ | |
| Secrets non hardcodés (truffleHog / gitleaks) | ⬜ | |
| Cookies signés HMAC (test de forge → rejet) | ⬜ | |
| Headers sensibles absents des logs | ⬜ | |
| API admin inaccessible sur port public | ⬜ | |
| Inputs validés contre le JSON Schema | ⬜ | |

### G6 — Performance
```bash
# Benchmark Go
go test -bench=. -benchmem ./internal/...

# Load test (k6)
k6 run tests/load/basic.js
```
| SLO | Target | Measured | Status |
|-----|--------|----------|--------|
| Latence P50 (visiteur connu) | < 1 ms | ⬜ ms | ⬜ |
| Latence P99 (visiteur connu) | < 5 ms | ⬜ ms | ⬜ |
| Débit (4 vCPU) | > 50 000 req/s | ⬜ req/s | ⬜ |
| Mémoire (100K visiteurs) | < 512 MB | ⬜ MB | ⬜ |
| Temps de démarrage | < 500 ms | ⬜ ms | ⬜ |

### G7 — PR Checklist (Human Review)
- [ ] Spec gap protocol appliqué si découverte de gap pendant l'implémentation
- [ ] Pas de code mort (dead code supprimé)
- [ ] Pas de logs de debug laissés
- [ ] Migration / breaking change documentés si applicable
- [ ] `configs/config.example.yaml` à jour
- [ ] README à jour si comportement externe change

---

## Test Plan

### Tests unitaires (objectif : 80% coverage)

| Package | Tests critiques |
|---------|----------------|
| `internal/middleware/challenge` | PoW validation, token expiry, cookie HMAC |
| `internal/middleware/ratelimit` | Token bucket, burst, recovery |
| `internal/trust` | Score transitions, TTL expiry |
| `internal/middleware/antibot` | UA detection, honeypot, header checks |
| `internal/signing` | HMAC sign/verify, tampered payload |
| `internal/config` | Valid config, missing fields, env override |

### Tests d'intégration

| Scénario | Setup | Assert |
|----------|-------|--------|
| Flow complet challenge | httptest serveur WAF + upstream mock | Cookie émis, redirect vers URL originale |
| Cookie forgé rejeté | Requête avec cookie HMAC invalide | Page challenge re-servie |
| IP blacklistée | Blacklist configurée | HTTP 403 |
| IP whitelistée | Whitelist configurée | Proxy immédiat, score non calculé |
| Honeypot path | /.env demandé | HTTP 403, score = 0 |
| Rate limit | 150 req/s sur bucket 100 | 100 OK + 50 × 429 |
| Googlebot whitelist UA | User-Agent Googlebot | Proxy immédiat |

### Tests de charge (k6)

**Scénario nominal (100 VUs, 5 min) :**
- 80% de visiteurs avec cookie valide → latence < 5 ms P99
- 20% de nouveaux visiteurs → challenge servi

**Scénario DDoS simulé (1000 VUs, 30s) :**
- Rate limit déclenché, 429 retournés
- Pas de crash, pas de memory leak
- Latence dégradée mais stable

**Scénario bot (curl, python-requests, 500 VUs) :**
- Score décrémenté, challenges déclenchés
- Bots bloqués après N échecs

---

## Métriques Prometheus à monitorer en production

```promql
# Taux de requêtes bloquées (alerte si > 50%)
rate(waf_requests_total{action="BLOCK"}[5m]) /
rate(waf_requests_total[5m]) > 0.5

# Latence P99 > 10ms (alerte)
histogram_quantile(0.99, rate(waf_request_duration_seconds_bucket[5m])) > 0.01

# Visiteurs bloqués anormalement élevés
waf_visitors_by_state{state="BLOCKED"} > 1000
```
