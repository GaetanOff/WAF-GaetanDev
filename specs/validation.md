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
| 2026-06-04 | Slice 2.2 | `go test ./...` | pass | Includes HeadlessChrome -30, python-requests -15, missing UA, missing headers, honeypot 403, Selenium block, whitelist bypass |
| 2026-06-04 | Slice 2.2 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 2.2 | `go build -o waf ./cmd/waf` | pass | AntiBot middleware wired after rate limit and before TrustScore |
| 2026-06-04 | Slice 2.3 | `go test ./...` | pass | Includes HMAC sign/verify, signed cookie issue/validate, expiry, forged HMAC, IP/domain mismatch |
| 2026-06-04 | Slice 2.3 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 2.3 | `go build -o waf ./cmd/waf` | pass | Signing and cookie packages compile into the WAF binary |
| 2026-06-04 | Slice 2.4 | `go test ./...` | pass | Includes HMAC token generation/validation, TTL expiry, IP/domain mismatch, and PoW known vectors |
| 2026-06-04 | Slice 2.4 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 2.4 | `go build -o waf ./cmd/waf` | pass | Challenge token and PoW packages compile into the WAF binary |
| 2026-06-04 | Slice 2.5 | `go test ./...` | pass | Includes challenge page, `/waf/verify` success, Set-Cookie, redirect, valid cookie pass, token/Pow/timing errors |
| 2026-06-04 | Slice 2.5 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 2.5 | `go build -o waf ./cmd/waf` | pass | Challenge middleware wired after access and before rate/antibot/trust |
| 2026-06-04 | Slice 2.5 | Runtime challenge page request | pass | No-cookie request returned 200 challenge page with branding and token |
| 2026-06-04 | Slice 2.6 | `go test ./...` | pass | Includes fingerprint parsing, canonical hash, invalid shape rejection, and headless WebGL rejection with score -30 |
| 2026-06-04 | Slice 2.6 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 2.6 | `go build -o waf ./cmd/waf` | pass | Fingerprint validation integrated into `/waf/verify` |
| 2026-06-04 | Slice 3.1 | `go test ./...` | pass | Includes circuit breaker open after 5 violations, middleware 403 `CIRCUIT_BREAK`, and 300s expiry |
| 2026-06-04 | Slice 3.1 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 3.1 | `go build -o waf ./cmd/waf` | pass | AntiDDoS circuit breaker wired into the public middleware pipeline |
| 2026-06-04 | Slice 3.2 | `go test ./...` | pass | Includes global sliding-window detector, config validation, 503 degraded response for new visitors, and known-visitor bypass |
| 2026-06-04 | Slice 3.2 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 3.2 | `go build -o waf ./cmd/waf` | pass | Global degraded mode wired before the challenge middleware |
| 2026-06-04 | Slice 4.1 | `go test ./...` | pass | Includes structured JSON security events, UUID request IDs, required schema fields, action/reason capture, and query-string redaction |
| 2026-06-04 | Slice 4.1 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 4.1 | `go build -o waf ./cmd/waf` | pass | Zerolog-based security logger wired into the public middleware pipeline |
| 2026-06-04 | Slice 4.2 | `go test ./...` | pass | Includes Prometheus counters, histogram buckets, active visitor gauges, visitor-state gauges, and `/waf/metrics` handler |
| 2026-06-04 | Slice 4.2 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 4.2 | `go build -o waf ./cmd/waf` | pass | Prometheus metrics middleware and endpoint wired into the public server |
| 2026-06-04 | Slice 4.3 | `go test ./...` | pass | Includes admin Bearer auth, blacklist CRUD, whitelist CRUD, visitors, stats, and config secret masking |
| 2026-06-04 | Slice 4.3 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 4.3 | `go build -o waf ./cmd/waf` | pass | Separate admin server wired on `server.admin_listen` |
| 2026-06-04 | Slice 5.1 | `go test ./...` | pass | Conformance suite derived from js-challenge.feature added (real template branding/timer, no external resources, forged/expired cookie, malformed/forged submission, NewMiddleware errors) |
| 2026-06-04 | Slice 5.1 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 5.1 | `go test -cover` (target packages) | pass | `trust` 88.9%, `middleware/challenge` 86.7% (up from 75.4%), `middleware/ratelimit` 93.9% — all ≥ 80% |
| 2026-06-04 | Slice 5.2 | `.github/workflows/ci.yml` authored | n/a | Jobs: lint (golangci-lint v1.62.2), test (`-race -coverprofile`), build (static linux), spec-lint (spectral) |
| 2026-06-04 | Slice 5.2 | `CGO_ENABLED=0 GOOS=linux go build ./cmd/waf` | pass | Mirrors the CI build job locally |
| 2026-06-04 | Slice 5.2 | golangci-lint / spectral | not run | Tools not installed locally; executed by the CI jobs on push/PR |
| 2026-06-04 | Slice 5.3 | `CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" ./cmd/waf` | pass | Static Linux binary builds for the distroless runtime stage |
| 2026-06-04 | Slice 5.3 | `go test ./...` | pass | Added `runHealthCheck` test (200 → ok, 503 → error, unreachable → error) |
| 2026-06-04 | Slice 5.3 | `go vet ./...` | pass | No vet findings |
| 2026-06-04 | Slice 5.3 | `docker build` | not run | Docker Desktop Linux engine not running locally; Dockerfile/compose authored against the verified static build |
| 2026-06-04 | Slice 5.4 | README + nginx guide + changelog authored | n/a | README (archi, quick start, Cloudflare deploy, admin, tests, layout), `deploy/nginx/upstream.conf.example`, `specs/changelog.md` [0.1.0] |
| 2026-06-04 | CI fix | `spectral lint specs/api/admin.openapi.yaml --ruleset .spectral.yaml` | pass | Was 3 errors + 14 warnings. Fixed: quoted description with inline colon (L48), moved `components.responses.Unauthorized` from under `paths` to top-level `components`, added `description` to all 14 operations. Now "No results with a severity of 'error' found!". OpenAPI `info.version` 1.0.0 → 1.0.1 |
| 2026-06-04 | CI fix | `golangci-lint run` (bodyclose) | pass (local proxy) | `response.Result()` body now captured and closed in `middleware_test.go`; `go test ./...` + `go vet ./...` green locally (golangci runs in CI) |
| 2026-06-04 | ADR-014 | `go test ./internal/logger/...` | pass | Migration zerolog → `log/slog`. New conformance test asserts emitted keys ⊆ security-event schema and that `time`/`level`/`msg` are stripped |
| 2026-06-04 | ADR-014 | `go mod tidy` + `go build ./cmd/waf` | pass | `github.com/rs/zerolog` (+ transitive `mattn/go-colorable`, `mattn/go-isatty`) removed from go.mod/go.sum |
| 2026-06-04 | ADR-014 | `go test ./...` + `go vet ./...` | pass | Full suite green after logging migration |
| 2026-06-08 | Spec review (risk engine) | Revue de cohérence requirements-detection.md + ADR-015 | pass (corrigé) | 4 constats bloquants traités : (1) réconciliation FR-05 — le moteur supersède le block mono-signal de `ScoreManager.State()` ; (2) 429/503 volumétriques orthogonaux à la corroboration ; (3) **bug FR-36** : crawler `pending` → OBSERVE, jamais de challenge JS ; (4) contrat de config `risk_engine` ajouté. Statuts : requirements-detection.md → approved v1.0.0, ADR-015 → accepted |

| 2026-06-08 | Slice 6.1 | `go test ./...` | pass | Added `internal/risk` signal interface and `RiskAssessment`; includes schema-oriented serialization tests against `schemas/risk-assessment.schema.json`, neutral defaults for absent families, contribution bounds, score/confidence clamps, and corroborating-family count |
| 2026-06-08 | Slice 6.1 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 6.2 | `go test ./...` | pass | Added weighted risk fusion, confidence calculation, lenient/balanced/strict profiles, runtime config conversion, `risk_engine` config validation, and example config coverage |
| 2026-06-08 | Slice 6.2 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 6.2 | `go build -o waf.exe ./cmd/waf` | pass | Binary builds after `risk_engine` config model and fusion package changes |
| 2026-06-08 | Slice 6.3 | `go test ./...` | pass | Added decision-tier mapping from `(risk_score, confidence)` to graduated mitigations; includes Scenario Outline examples from `risk-scoring-engine.feature`, configurable/profiled tiers, low-confidence cap at CHALLENGE, and RiskAssessment update helper |
| 2026-06-08 | Slice 6.3 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 6.3 | `go build -o waf.exe ./cmd/waf` | pass | Binary builds after decision mapping package changes |
| 2026-06-08 | Slice 6.4 | `go test ./...` | pass | Added FR-35 decision guards: heuristic BLOCK requires configured corroborating families, isolated heuristic signal caps at CHALLENGE, deterministic triggers can BLOCK without corroboration, and low confidence prevents BLOCK |
| 2026-06-08 | Slice 6.4 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 6.4 | `go build -o waf.exe ./cmd/waf` | pass | Binary builds after corroboration and deterministic-trigger decision changes |
| 2026-06-08 | Slice 6.5 | `go test ./...` | pass | Added async reverse-DNS/forward-confirm bot verifier with TTL cache, verified-bot ALLOW guard, pending OBSERVE cap, and spoofed crawler reputation contribution using mocked resolver tests |
| 2026-06-08 | Slice 6.5 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 6.5 | `go build -o waf.exe ./cmd/waf` | pass | Binary builds after verified bot package changes |
| 2026-06-08 | Slice 6.6 | `go test ./...` | pass | Added human proof credits, sticky trust TTL state, visitor schema field, heuristic BLOCK cap for human credit, deterministic-trigger sticky-trust revocation behavior, and storage-backed tests |
| 2026-06-08 | Slice 6.6 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 6.6 | `go build -o waf.exe ./cmd/waf` | pass | Binary builds after human credit and visitor state changes |
| 2026-06-08 | Slice 6.7 | `go test ./...` | pass | Added risk decision middleware, pipeline wiring before proxy, Trust Score fallback when disabled, condensed RiskAssessment headers, `score_delta` logging, and httptest route/middleware coverage |
| 2026-06-08 | Slice 6.7 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 6.7 | `go build -o waf.exe ./cmd/waf` | pass | Binary builds after risk middleware pipeline integration |
| 2026-06-08 | Slice 6.8 | `go test ./...` | pass | Added risk shadow mode, security-event risk fields, bounded feedback weight decay, FR-38 Prometheus counters, and tests for shadow non-application, feedback bounds, and metrics |
| 2026-06-08 | Slice 6.8 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 6.8 | `go build -o waf.exe ./cmd/waf` | pass | Binary builds after shadow/feedback/metrics changes |
| 2026-06-08 | Slice 7.1 | `go test ./...` | pass | Detector signal adapters: antibot publishes fingerprint contribution + honeypot trigger, blacklist/circuit triggers, ratelimit rate contribution. Updated `TestRoutesAppliesRiskDecisionBeforeProxy` (antibot now owns the fingerprint signal) |
| 2026-06-08 | Slice 7.1 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 7.1 | `go build -o waf.exe ./cmd/waf` | pass | Binary builds after signal-adapter changes |
| 2026-06-08 | Slice 7.2 | `go test ./...` | pass | Shadow-by-default config; end-to-end tests: shadow not enforced (`X-WAF-Risk-Shadow-Mode`), corroborated block from real reputation+rate signals (`X-WAF-Risk-Corroborated`), enforcement test pins shadow off |
| 2026-06-08 | Slice 7.2 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 7.2 | `go build -o waf.exe ./cmd/waf` | pass | Binary builds after shadow-default + integration tests |
| 2026-06-08 | fix(risk) | `go test ./internal/risk/...` | pass | Fixed real-clock-dependent human-trust tests (future-dated fixture) |
| 2026-06-08 | Slice 8.1 | `go test ./...` | pass | New `internal/integrity` (FR-18): traversal/null-byte/injection/length detection, decoded-form analysis, integrity risk contribution, 10MB body limit (413). `routes()` gains a `detectors` chain run before the risk engine |
| 2026-06-08 | Slice 8.1 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 8.1 | `go build -o waf.exe ./cmd/waf` | pass | Binary builds; integrity wired as first Phase 8 detector |
| 2026-06-08 | Slice 8.2 | `go test ./...` | pass | New `internal/behavioral` (FR-12): async ring-buffer tracker, 6 anomaly signals, score applied to next request via `X-WAF-Risk-behavioral`; stop-channel shutdown (queue never closed) |
| 2026-06-08 | Slice 8.2 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 8.2 | `go build -o waf.exe ./cmd/waf` | pass | Behavioral wired as Phase 8 detector |
| 2026-06-08 | Slice 8.3 | `go test ./...` | pass | New `internal/threatintel` (FR-13): async TTL-cached checker, local CIDR feeds + AbuseIPDB HTTP source; critical→deterministic trigger, else idempotent trust ceiling. 100% stdlib (no maxminddb) |
| 2026-06-08 | Slice 8.3 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 8.3 | `go build -o waf.exe ./cmd/waf` | pass | Threat-intel wired as opt-in Phase 8 detector |
| 2026-06-08 | Slice 8.4 | `go test ./...` | pass | New `internal/adaptive` (FR-14): attack-intensity controller, immediate rise + exponential decay, difficulty embedded in signed token (anti-downgrade), `waf_challenge_pow_difficulty` gauge |
| 2026-06-08 | Slice 8.4 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 8.4 | `go build -o waf.exe ./cmd/waf` | pass | Adaptive difficulty wired into challenge + metrics |
| 2026-06-08 | Slice 8.5 | `go test ./...` | pass | New `internal/geo` (FR-16): CF-IPCountry rules (whitelist/block/challenge), geo risk contribution, graceful no-header pass |
| 2026-06-08 | Slice 8.5 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 8.5 | `go build -o waf.exe ./cmd/waf` | pass | Geo wired as opt-in Phase 8 detector |
| 2026-06-08 | Slice 8.6 | `go test ./...` | pass | New `internal/tlsfp` (FR-11): JA3 string/hash utils, CF JA3 header read, JA3 blacklist→deterministic trigger, JA3 swap detection→tls contribution |
| 2026-06-08 | Slice 8.6 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 8.6 | `go build -o waf.exe ./cmd/waf` | pass | TLS fingerprint wired as Phase 8 detector |
| 2026-06-08 | Slice 8.7 | `go test ./...` | pass | New `internal/deception` (FR-15): tarpit (chunked slow fake HTML), connection semaphore (NFR-10, 429 when full), wired via Dispatch wrapping the proxy on TARPIT tier |
| 2026-06-08 | Slice 8.7 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 8.7 | `go build -o waf.exe ./cmd/waf` | pass | Tarpit dispatch wraps proxy before the risk engine |
| 2026-06-08 | Slice 8.8 | `go test ./...` | pass | New `internal/rules` (FR-17): YAML DSL compiled to structs (regex/CIDR precompiled), priority + short-circuit, conditions/actions subset, atomic hot-reload |
| 2026-06-08 | Slice 8.8 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 8.8 | `go build -o waf.exe ./cmd/waf` | pass | Rules engine wired as opt-in Phase 8 detector |
| 2026-06-08 | Slice 8.9 | `go test ./...` | pass | New `internal/origin` (FR-19): hourly-rotating HMAC origin token (2h tolerance), injector to upstream, `/waf/origin/verify` endpoint, `WAF_ORIGIN_SECRET` env override |
| 2026-06-08 | Slice 8.9 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 8.9 | `go build -o waf.exe ./cmd/waf` | pass | Origin protection wired in routes() (verify endpoint + injector) |
| 2026-06-08 | Slice 8.10 | `go mod tidy` | pass | Added `github.com/redis/go-redis/v9` v9.7.0 (+ transitive deps) |
| 2026-06-08 | Slice 8.10 | `go test ./...` | pass | New `internal/cluster` (FR-20): Event model, Bus iface, LocalBus + RedisBus (Pub/Sub), Syncer applies inbound blacklist/score, `RuleSet.AddBlacklist`, `waf_cluster_sync_events_total` metric |
| 2026-06-08 | Slice 8.10 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 8.10 | `go build -o waf.exe ./cmd/waf` | pass | Cluster subscriber wired (autonomous fallback if Redis down). Phase 8 complete |
| 2026-06-08 | Slice 9.1 | `go test ./...` | pass | New `internal/secheaders` (FR-21/22): sanitizing response writer, security headers injected if absent (upstream priority), Server/X-Powered-By stripped, CSP opt-in |
| 2026-06-08 | Slice 9.1 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 9.1 | `go build -o waf.exe ./cmd/waf` | pass | Security headers wrap the whole mux (outermost) |
| 2026-06-08 | Slice 9.2 | `go test ./...` | pass | New `internal/slowloris` (FR-23): per-IP concurrency limiter (429 over limit), configurable ReadHeaderTimeout; per-IP isolation tested |
| 2026-06-08 | Slice 9.2 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 9.2 | `go build -o waf.exe ./cmd/waf` | pass | Slowloris limiter wired under security headers |
| 2026-06-08 | Slice 9.3 | `go test ./...` | pass | New `internal/staticassets` (FR-24): asset extensions marked PASS upstream of challenge/trust, blacklist still applied |
| 2026-06-08 | Slice 9.3 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 9.3 | `go build -o waf.exe ./cmd/waf` | pass | Static bypass wired as outermost proxy-chain middleware |
| 2026-06-08 | Slice 9.4 | `go test ./...` | pass | New `internal/upstream` (FR-25/26): pool with per-upstream health (atomic), round_robin/least_conn/ip_hash/weighted, backup fallback, active HealthChecker; proxy `WithPool` health-aware selection + failover ErrorHandler |
| 2026-06-08 | Slice 9.4 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 9.4 | `go build -o waf.exe ./cmd/waf` | pass | Upstream pool wired into proxy + boot health checker |
| 2026-06-08 | Slice 9.5 | `go test ./...` | pass | New `internal/audit` (FR-27): append-only FIFO trail, secret masking, optional file; wired into admin mutations + `GET /waf/admin/audit` |
| 2026-06-08 | Slice 9.5 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 9.5 | `go build -o waf.exe ./cmd/waf` | pass | Audit trail wired into admin server |
| 2026-06-08 | Slice 9.6 | `go test ./...` | pass | New `internal/gdpr` (FR-28): IP anonymization /24 & /48, logger anonymizes IP field, admin erasure endpoint, register of treatments doc |
| 2026-06-08 | Slice 9.6 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 9.6 | `go build -o waf.exe ./cmd/waf` | pass | GDPR anonymization wired into logger; erasure endpoint in admin |
| 2026-06-08 | Slice 9.7 | `go test ./...` | pass | New `internal/alert` (FR-29): async notifier, Slack/Discord/generic sinks, exponential-backoff retry, cooldown dedup; logger emits on high-severity actions. httptest-covered |
| 2026-06-08 | Slice 9.7 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 9.7 | `go build -o waf.exe ./cmd/waf` | pass | Alerting wired to logger via Alerter interface |
| 2026-06-08 | Slice 9.8 | `go test ./...` | pass | New `internal/selfprotect` (FR-30): per-IP fixed-window counter, PathGuard for /waf/verify flood, admin brute-force lockout in admin.auth |
| 2026-06-08 | Slice 9.8 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 9.8 | `go build -o waf.exe ./cmd/waf` | pass | Verify flood guard + admin brute-force wired |
| 2026-06-08 | Slice 9.9 | `go mod tidy` | pass | Added `golang.org/x/crypto@v0.31.0` (pinned for go 1.22; autocert). go directive stays 1.22 |
| 2026-06-08 | Slice 9.9 | `go test ./...` | pass | New `internal/acme` (FR-31): autocert manager (TLSConfig + HTTP-01 handler), native auto-renewal/hot rotation; wired into dual-port serve when enabled |
| 2026-06-08 | Slice 9.9 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 9.9 | `go build -o waf.exe ./cmd/waf` | pass | ACME TLS + HTTP-01 challenge server wired (opt-in) |
| 2026-06-08 | Slice 9.10 | `go test ./...` | pass | New `internal/maintenance` (FR-32): maintenance-mode 503 branded page (internal endpoints exempt), error-body replacement (4xx/5xx plain text -> branded HTML), 2xx & existing-HTML preserved |
| 2026-06-08 | Slice 9.10 | `go vet ./...` | pass | No vet findings |
| 2026-06-08 | Slice 9.10 | `go build ./...` | pass | Maintenance middleware wired between slowloris and security headers |
| 2026-06-09 | Spec review (adaptive global pressure) | Revue requirements.md FR-08 + ADR-016 + anti-ddos.feature | pass | Breaking spec change accepted: global traffic pressure no longer emits automatic 503/403; pressure is adaptive signal for risk/challenge/PoW/metrics/logs |
| 2026-06-09 | Slice 10.1 | `go test ./...` | pass | Replaced global degraded 503 with bounded bucket pressure detector; tests cover no global 503, pressure headers, rate contribution, metrics/log field, and config validation |
| 2026-06-09 | Slice 10.1 | `go vet ./...` | pass | No vet findings |
| 2026-06-09 | Slice 10.1 | `go build -o waf.exe ./cmd/waf` | pass | Binary builds after adaptive pressure integration |
| 2026-06-09 | Slice 10.1 | JSON schema parse | pass | `specs/schemas/config.schema.json` and `specs/schemas/security-event.schema.json` parse successfully |
| 2026-06-09 | Slice 10.1 (code review) | `go test ./... && go vet ./...` | pass | Post-implementation review fixes: real THROTTLE in ratelimit (rate+capacity ×0.8/0.5/0.25 for non-TRUSTED, recomputed per request → reversible); adaptive bug fixed (high≠critical, +highExtraBits=6); removed dead `statusRecorder.Write` no-op; added ratelimit + adaptive pressure tests |
| 2026-06-10 | Slice 11.1 | `go test ./...` | pass | FR-33 per-domain TLS via SNI: new `internal/tlsmgr` (load PEM pairs, GetCertificate by SNI exact+wildcard, default fallback / reject), config `server.tls`+`domains[].tls` with fail-fast validation, `waf_tls_cert_expiry_seconds{domain}` metric, HTTP→HTTPS redirect |
| 2026-06-10 | Slice 11.1 | `go vet ./...` | pass | No vet findings |
| 2026-06-10 | Slice 11.1 | smoke test (openssl s_client) | pass | Live TLS handshake: SNI alpha→cert alpha, SNI beta→cert beta, unknown SNI→TLS alert (no cert served), HTTP→HTTPS 301 |
| 2026-06-10 | FR-01 `upstream.preserve_host` | `go test ./... && go vet ./...` | pass | New option to forward the inbound Host to the upstream (vhost routing). Threaded through newReverseProxy + WithPool; table test asserts default rewrites to upstream host and preserve_host keeps inbound host |
| 2026-06-10 | FR-06 challenge no-store | `go test ./internal/middleware/challenge/` | pass | Challenge page + /waf/verify (success & error) now send Cache-Control: no-store / Pragma / Expires; tests assert no-store on page and on verify error. Prevents CDN caching an expired IP-bound token (challenge loop) |

## Security Scan Triage (Semgrep OSS)

Décisions sur les findings remontés par le workflow Semgrep en code scanning.
Chaque suppression (`nosemgrep`) est explicite et justifiée (SDD : pas de
modification silencieuse, décisions tracées).

| Date | Finding (rule id) | Fichier | Décision | Justification |
|---|---|---|---|---|
| 2026-06-09 | `crypto...use-of-md5` | `internal/tlsfp/ja3.go` | Supprimé (`nosemgrep`) — faux positif | MD5 imposé par la spec JA3 ; identifiant de fingerprint (FR-11), pas une signature. SHA-256 casserait l'interop avec les feeds JA3 et `ja3_blacklist`. |
| 2026-06-09 | `net...cookie-missing-secure` | `internal/middleware/challenge/cookie.go` | Supprimé (`nosemgrep`) — faux positif | Match sur le `http.Cookie{}` vide du chemin d'erreur (jamais émis). Le cookie délivré active déjà `Secure: true`. |
| 2026-06-09 | `net...cookie-missing-httponly` | `internal/middleware/challenge/cookie.go` | Supprimé (`nosemgrep`) — faux positif | Idem : le cookie délivré active déjà `HttpOnly: true` (+ `SameSite=Lax`). L'OSS ne fait pas de dataflow. |
| 2026-06-09 | `nginx...header-redefinition` (x2) | `deploy/nginx/default.conf` | Corrigé | Remplacé `add_header Content-Type` (qui écrase les en-têtes du bloc server) par `default_type`, directive nginx idiomatique pour `return`. Origine de test du stack compose. |

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
