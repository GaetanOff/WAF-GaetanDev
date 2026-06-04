---
status: draft
sprint: 1
last-updated: 2026-06-04
---

# Tasks — WAF Anti-DDoS / Anti-Bot

## Sprint 1 — Fondations (Phase 1)

### T1.1 — Bootstrap projet Go
- [x] `go mod init github.com/gaetandev/waf`
- [x] Créer la structure de dossiers complète (cf. architecture.md)
- [x] `Makefile` : `build`, `test`, `lint`, `run`, `docker-build`
- [x] `cmd/waf/main.go` : bootstrap + SIGTERM graceful shutdown
- [x] `.gitignore` Go standard
- **Acceptance** : `make build` produit un binaire, `make test` passe
- **Validation 2026-06-04** : `go test ./...`, `go vet ./...`, `go build -o waf ./cmd/waf` passent. `make` non disponible localement.
- **Spec** : architecture.md

### T1.2 — Config loader + validation
- [x] Définir la struct `Config` (cf. config.schema.json)
- [x] `config.Load(path)` : YAML → struct
- [x] `config.Validate()` : erreurs explicites par champ
- [x] Overrides env vars (`WAF_CHALLENGE_SECRET_KEY`, `WAF_ADMIN_TOKEN`)
- [x] Tests unitaires : config valide, config manquante, champs invalides
- **Acceptance** : erreur claire si `challenge.secret_key` absent et env var non défini
- **Validation 2026-06-04** : `go test ./...`, `go vet ./...`, `go build -o waf ./cmd/waf` passent. Healthcheck OK avec config exemple et secrets via env.
- **Spec** : schemas/config.schema.json

### T1.3 — Reverse proxy + routing domaine
- [x] `proxy.Handler` : wrap `httputil.ReverseProxy` avec routing par Host header
- [x] Ajout headers : `X-Forwarded-For`, `X-Real-IP`, `X-WAF-Score`
- [x] Timeout configurable sur l'upstream
- [x] Gestion 502 si upstream down (pas de panic)
- [x] Tests avec `httptest.NewServer`
- **Acceptance** : une requête GET proxifiée → upstream reçoit les bons headers
- **Validation 2026-06-04** : `go test ./...`, `go vet ./...`, `go build -o waf ./cmd/waf` passent. Runtime proxy local OK avec headers `X-Forwarded-For`, `X-Real-IP`, `X-WAF-Score`.
- **Spec** : requirements FR-01

### T1.4 — Middleware Cloudflare IP
- [x] Embed statique des plages IPv4/IPv6 Cloudflare (cf. https://www.cloudflare.com/ips-v4)
- [x] Extraction `CF-Connecting-IP` si source ∈ ranges CF
- [x] Rejet 400 si tentative de forge depuis IP non-CF
- [x] Tests : IP CF valide, IP non-CF avec header CF, IP non-CF sans header
- **Acceptance** : `CF-Connecting-IP` utilisé comme IP réelle uniquement si source est Cloudflare
- **Validation 2026-06-04** : `go test ./...`, `go vet ./...`, `go build -o waf ./cmd/waf` passent. Runtime forge `CF-Connecting-IP` depuis localhost → 400.
- **Spec** : requirements FR-02

### T1.5 — Store in-memory + Whitelist/Blacklist
- [x] `storage.Store` interface : `GetVisitor`, `SetVisitor`, `DeleteVisitor`, `GetBucket`, `SetBucket`
- [x] `memory.Store` : `sync.Map` + goroutine nettoyage TTL (tick toutes les 60s)
- [x] LRU eviction si `max_visitors` atteint
- [x] `WhitelistMiddleware` : IP exact + CIDR + user-agent regex
- [x] `BlacklistMiddleware` : IP exact + CIDR → HTTP 403
- [x] Tests unitaires : matching CIDR, eviction LRU, TTL expiry
- **Acceptance** : IP en whitelist passe sans middleware, IP en blacklist → 403
- **Validation 2026-06-04** : `go test ./...`, `go vet ./...`, `go build -o waf ./cmd/waf` passent. Runtime blacklist locale `127.0.0.1` → 403.
- **Spec** : requirements FR-04, features/whitelist-blacklist.feature

### T1.6 — Rate Limiting Token Bucket
- [x] `bucket.TokenBucket` : atomic refill, `TryConsume() bool`
- [x] `RateLimitMiddleware` : HTTP 429 + `Retry-After: N` + décrémente score -10
- [x] Tests : burst autorisé, burst dépassé, récupération après 1s
- **Acceptance** : 150 req/s sur bucket de 100 → 100 OK + 50 × 429
- **Validation 2026-06-04** : `go test ./...`, `go vet ./...`, `go build -o waf ./cmd/waf` passent. Runtime `burst=1` → première requête 200, deuxième 429 avec `Retry-After=1`.
- **Spec** : requirements FR-03, features/anti-ddos.feature

---

## Sprint 2 — Intelligence (Phase 2)

### T2.1 — Score de confiance
- [x] `trust.ScoreManager` : Get/Set/Apply delta, State(), TTL expiry
- [x] Middleware TrustScore : lit état → PASS / CHALLENGE / BLOCK
- [x] Tests : transitions d'état, TTL expiry, clamp [0,100]
- **Validation 2026-06-04** : `go test ./...`, `go vet ./...`, `go build -o waf ./cmd/waf` passent. Runtime score initial 12 + rate limit → 403 `score_below_block_threshold`.
- **Spec** : requirements FR-05, features/trust-score.feature

### T2.2 — Anti-Bot rules
- [x] `antibot.Rules` : patterns headless UA, headers manquants, honeypot paths
- [x] Middleware AntiBot : applique les deltas de score
- [x] Honeypot : score = 0 + HTTP 403 + log HONEYPOT
- [x] Tests : HeadlessChrome -30, python-requests -15, Googlebot → pass
- **Validation 2026-06-04** : `go test ./...`, `go vet ./...`, `go build -o waf ./cmd/waf` passent. WebGL headless reste couvert par T2.6 Fingerprint.
- **Spec** : requirements FR-07, features/anti-bot.feature

### T2.3 — HMAC Signing + Cookie
- [x] `signing.Sign(key, payload) string` (HMAC-SHA256 base64url)
- [x] `signing.Verify(key, payload, sig) bool`
- [x] `cookie.Issue(ip, domain, fpHash, score, ttl) http.Cookie`
- [x] `cookie.Validate(cookieValue, ip, domain, key) (*Payload, error)`
- [x] Tests : cookie valide, TTL expiré, HMAC forgé, IP mismatch
- **Validation 2026-06-04** : `go test ./...`, `go vet ./...`, `go build -o waf ./cmd/waf` passent.
- **Spec** : requirements FR-06, architecture.md (Cookie structure)

### T2.4 — Challenge token + PoW validation
- [x] `nonce.Generate(ip, domain, key) string` : HMAC signé + TTL 30s
- [x] `nonce.Validate(token, ip, domain, key) error`
- [x] `pow.Validate(token, nonce string, difficultyBits int) bool`
- [x] Tests vecteurs PoW : nonce connu + hash attendu
- **Validation 2026-06-04** : `go test ./...`, `go vet ./...`, `go build -o waf ./cmd/waf` passent.
- **Spec** : requirements FR-06, ADR-003

### T2.5 — Page challenge + /waf/verify
- [x] `challenge.html` : template Go, injection Token/Difficulty/RedirectURL
- [x] Middleware Challenge : sert la page si pas de cookie valide
- [x] Handler `POST /waf/verify` : parse ChallengeSubmission, valide tout
- [x] On success : émet cookie + `{"redirect_url": "..."}` 200
- [x] On failure : erreur 400 avec code machine-readable
- [x] Tests d'intégration : flow complet challenge → cookie → pass
- **Validation 2026-06-04** : `go test ./...`, `go vet ./...`, `go build -o waf ./cmd/waf` passent. Runtime sans cookie → page challenge 200 avec token.
- **Spec** : requirements FR-06, features/js-challenge.feature, schemas/challenge-submission.schema.json

### T2.6 — Fingerprint validation
- [x] `fingerprint.Parse(submission)` : extrait et valide les signaux
- [x] `fingerprint.Hash(fp) string` : SHA-256 des 9 signaux
- [x] Détection WebGL headless : SwiftShader, llvmpipe → score -30
- [x] Intégration dans le verify handler
- **Validation 2026-06-04** : `go test ./...`, `go vet ./...`, `go build -o waf ./cmd/waf` passent. WebGL headless rejeté avec erreur `headless_webgl_renderer` et score -30.
- **Spec** : requirements FR-07, ADR-004

---

## Sprint 3 — Anti-DDoS avancé (Phase 3)

### T3.1 — Circuit Breaker
- [ ] `breaker.CircuitBreaker` : `RecordViolation()`, `IsOpen() bool`, TTL fermeture
- [ ] Middleware AntiDDoS : ouvre le circuit après N violations, HTTP 403
- [ ] Tests : 5 violations → circuit ouvert, expiration → circuit fermé
- **Spec** : requirements FR-08, features/anti-ddos.feature

### T3.2 — Mode dégradé global
- [ ] `antiddos.GlobalRateDetector` : sliding window, compteur req/s global
- [ ] Si dépassement seuil : nouveaux visiteurs → 503 + Retry-After
- **Spec** : requirements FR-08

---

## Sprint 4 — Observabilité (Phase 4)

### T4.1 — Logger structuré
- [ ] Wrapper `zerolog` avec `request_id` UUID v4 par requête
- [ ] Middleware de logging : log JSON conforme au schéma security-event.schema.json
- [ ] Pas de query string dans les logs INFO (seulement path)
- [ ] Tests : format JSON valide, champs requis présents
- **Spec** : requirements FR-09, schemas/security-event.schema.json

### T4.2 — Métriques Prometheus
- [ ] Counters : `waf_requests_total`, `waf_blocked_total`, `waf_challenged_total`
- [ ] Histogram : `waf_request_duration_seconds`
- [ ] Gauges : `waf_active_visitors`, `waf_visitors_by_state{state}`
- [ ] `GET /waf/metrics` handler
- **Spec** : requirements FR-09

### T4.3 — API Admin complète
- [ ] Serveur HTTP séparé `:9090` avec auth Bearer
- [ ] Tous les endpoints de `specs/api/admin.openapi.yaml`
- [ ] Tests : auth invalide → 401, opérations CRUD whitelist/blacklist
- **Spec** : requirements FR-10, api/admin.openapi.yaml

---

## Sprint 5 — Production (Phase 5)

### T5.1 — Tests de conformance Gherkin
- [ ] Tests couvrant tous les scénarios de `specs/features/*.feature`
- [ ] Coverage ≥ 80% sur packages `trust`, `middleware/challenge`, `middleware/ratelimit`
- **Spec** : core-quality-gates.mdc, global-testing.mdc

### T5.2 — CI GitHub Actions
- [ ] Job lint : `golangci-lint run`
- [ ] Job test : `go test ./... -race -coverprofile=coverage.out`
- [ ] Job build : `CGO_ENABLED=0 GOOS=linux go build -o waf ./cmd/waf`
- [ ] Job spec-lint : `spectral lint specs/api/admin.openapi.yaml`
- **Spec** : core-devops.mdc

### T5.3 — Docker
- [ ] `Dockerfile` multi-stage : builder Go + image distroless/scratch
- [ ] Image finale < 30 MB
- [ ] `docker-compose.yml` : waf + nginx upstream de test
- [ ] `HEALTHCHECK` sur `/waf/health`
- **Spec** : requirements NFR-05

### T5.4 — Documentation
- [ ] `README.md` : installation, configuration, déploiement Cloudflare
- [ ] `configs/config.example.yaml` finalisé
- [ ] Guide nginx.conf minimal pour l'upstream
- [ ] Changelog initial v0.1.0
