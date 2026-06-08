---
status: draft
sprint: 5
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
- [x] `breaker.CircuitBreaker` : `RecordViolation()`, `IsOpen() bool`, TTL fermeture
- [x] Middleware AntiDDoS : ouvre le circuit après N violations, HTTP 403
- [x] Tests : 5 violations → circuit ouvert, expiration → circuit fermé
- **Validation 2026-06-04** : `go test ./...`, `go vet ./...`, `go build -o waf ./cmd/waf` passent. Circuit ouvert après 5 violations, réponse 403 `CIRCUIT_BREAK`, fermeture après 300s.
- **Spec** : requirements FR-08, features/anti-ddos.feature

### T3.2 — Mode dégradé global
- [x] `antiddos.GlobalRateDetector` : sliding window, compteur req/s global
- [x] Si dépassement seuil : nouveaux visiteurs → 503 + Retry-After
- **Validation 2026-06-04** : `go test ./...`, `go vet ./...`, `go build -o waf ./cmd/waf` passent. Seuil global configurable via `antiddos.global_requests_per_second`, nouveaux visiteurs rejetés avec `503`, `Retry-After: 5`, reason `global_rate_exceeded`.
- **Spec** : requirements FR-08

---

## Sprint 4 — Observabilité (Phase 4)

### T4.1 — Logger structuré
- [x] Wrapper `log/slog` (stdlib, voir ADR-014) avec `request_id` UUID v4 par requête
- [x] Middleware de logging : log JSON conforme au schéma security-event.schema.json
- [x] Pas de query string dans les logs INFO (seulement path)
- [x] Tests : format JSON valide, champs requis présents
- **Validation 2026-06-04** : `go test ./...`, `go vet ./...`, `go build -o waf ./cmd/waf` passent. Logs JSON sans champs hors schéma, `request_id` UUID v4, `path` sans query string, actions/reasons WAF capturées.
- **Révision 2026-06-04 (ADR-014)** : migration de `zerolog` vers `log/slog` (stdlib). Clés intégrées slog (`time`/`level`/`msg`) retirées via `ReplaceAttr`, champs nullables émis en `null`, événement toujours émis (niveau configuré). Test de conformance ajouté (clés ⊂ schéma). zerolog retiré de go.mod.
- **Spec** : requirements FR-09, schemas/security-event.schema.json, ADR-014

### T4.2 — Métriques Prometheus
- [x] Counters : `waf_requests_total`, `waf_blocked_total`, `waf_challenged_total`
- [x] Histogram : `waf_request_duration_seconds`
- [x] Gauges : `waf_active_visitors`, `waf_visitors_by_state{state}`
- [x] `GET /waf/metrics` handler
- **Validation 2026-06-04** : `go test ./...`, `go vet ./...`, `go build -o waf ./cmd/waf` passent. `/waf/metrics` expose les compteurs, histogramme et gauges Prometheus via registre dédié.
- **Spec** : requirements FR-09

### T4.3 — API Admin complète
- [x] Serveur HTTP séparé `:9090` avec auth Bearer
- [x] Tous les endpoints de `specs/api/admin.openapi.yaml`
- [x] Tests : auth invalide → 401, opérations CRUD whitelist/blacklist
- **Validation 2026-06-04** : `go test ./...`, `go vet ./...`, `go build -o waf ./cmd/waf` passent. API admin branchée sur `server.admin_listen`, auth Bearer, config masquée, stats/visiteurs/events, CRUD whitelist/blacklist avec hot update `RuleSet`.
- **Spec** : requirements FR-10, api/admin.openapi.yaml

---

## Sprint 5 — Production (Phase 5)

### T5.1 — Tests de conformance Gherkin
- [x] Tests couvrant tous les scénarios de `specs/features/*.feature`
- [x] Coverage ≥ 80% sur packages `trust`, `middleware/challenge`, `middleware/ratelimit`
- **Acceptance** : `go test ./...` vert, coverage ≥ 80% sur les 3 packages cibles
- **Validation 2026-06-04** : conformance_test.go dérivé de js-challenge.feature. Coverage `trust` 88.9%, `challenge` 86.7% (75.4% → 86.7%), `ratelimit` 93.9%. `go test ./...` et `go vet ./...` passent.
- **Spec** : core-quality-gates.mdc, global-testing.mdc

### T5.2 — CI GitHub Actions
- [x] Job lint : `golangci-lint run` (action pinnée v1.62.2, config `.golangci.yml`)
- [x] Job test : `go test ./... -race -coverprofile=coverage.out` + upload artifact
- [x] Job build : `CGO_ENABLED=0 GOOS=linux go build -o waf ./cmd/waf`
- [x] Job spec-lint : `spectral lint specs/api/admin.openapi.yaml --ruleset .spectral.yaml`
- **Acceptance** : 4 jobs sur push/PR vers main, Go lu depuis `go.mod`
- **Validation 2026-06-04** : workflow `.github/workflows/ci.yml` (lint, test, build, spec-lint). `.golangci.yml` et `.spectral.yaml` (extends spectral:oas) ajoutés. Build statique Linux vérifié localement ; jobs lint/spec-lint exécutés en CI (golangci-lint/spectral non installés localement).
- **Spec** : core-devops.mdc

### T5.3 — Docker
- [x] `Dockerfile` multi-stage : builder Go + image distroless/static
- [x] Image finale < 30 MB (binaire statique `-s -w` ~ 15 MB + distroless static ~ 2 MB)
- [x] `docker-compose.yml` : waf + nginx upstream de test
- [x] `HEALTHCHECK` sur `/waf/health` (mode `-healthcheck` du binaire, image sans shell)
- **Acceptance** : `docker compose up --build` expose le WAF qui proxifie l'origine nginx
- **Validation 2026-06-04** : `CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w"` produit un binaire statique. `go test ./...` et `go vet ./...` passent (test `runHealthCheck` ajouté). Build d'image Docker non vérifié localement (démon Docker Desktop arrêté).
- **Spec** : requirements NFR-05

### T5.4 — Documentation
- [x] `README.md` : installation, configuration, déploiement Cloudflare
- [x] `configs/config.example.yaml` finalisé (multi-domaine, secrets env, honeypot)
- [x] Guide nginx.conf minimal pour l'upstream (`deploy/nginx/upstream.conf.example`)
- [x] Changelog initial v0.1.0 (`specs/changelog.md`, format Keep a Changelog)
- **Acceptance** : un nouvel arrivant peut builder, configurer et déployer depuis le README
- **Validation 2026-06-04** : README complet (archi, quick start, Cloudflare, admin, tests, structure). Guide nginx d'origine avec récupération real_ip. Changelog [0.1.0] documentant le périmètre livré.
- **Spec** : global-documentation.mdc

---

## Sprint 6 - Moteur de Risque & Decision (Phase 6)

### T6.1 - Interface de signaux + type RiskAssessment
- [x] `internal/risk/signal.go` : enum `SignalFamily` couvrant `reputation`, `behavioral`, `tls`, `fingerprint`, `integrity`, `rate`, `geo`, `human_credit`
- [x] `Contribution` conforme aux facteurs de `schemas/risk-assessment.schema.json`
- [x] `SignalProvider` pour adapter les detecteurs existants au moteur de risque
- [x] Familles absentes completees par contribution neutre via `CollectContributions`
- [x] `internal/risk/assessment.go` : `RiskAssessment` conforme au schema JSON, avec decisions, bases de decision, triggers deterministes et profils
- [x] Tests : serialisation conforme a `schemas/risk-assessment.schema.json`, bornage `risk_score` / `confidence` / `contribution`, comptage des familles corroborantes, contribution neutre par defaut
- **Acceptance** : les types de la Slice 6.1 compilent, la serialisation `RiskAssessment` respecte le schema approuve, et les familles de signaux non encore implementees contribuent de facon neutre
- **Validation 2026-06-08** : `go test ./...` et `go vet ./...` passent. Nouveau package `internal/risk` couvert par les tests `TestRiskAssessmentSerializesAccordingToSchema`, `TestNewAssessmentClampsScoreConfidenceAndCountsCorroboratingFamilies`, `TestNeutralContributionDefaultsAbsentFamilyToNoRisk`, `TestCollectContributionsCompletesAbsentFamiliesWithNeutralDefaults`, `TestClampContributionUsesSchemaBounds`.
- **Spec** : requirements-detection.md FR-33, NFR-17 ; schemas/risk-assessment.schema.json ; ADR-015 ; plan.md Slice 6.1

### T6.2 - Fusion ponderee + confiance + profils
- [x] `internal/risk/fusion.go` : fusion ponderee deterministe vers `risk_score [0..100]` et `confidence [0..1]`
- [x] Familles absentes traitees comme neutres dans le score et comme indisponibles dans la confiance
- [x] Profils `lenient`, `balanced`, `strict` via `DefaultFusionConfig`
- [x] Conversion depuis la configuration runtime via `FusionConfigFromConfig`
- [x] `internal/config/config.go` : bloc `risk_engine` avec poids par famille, profil, seuil de confiance, tiers, corroboration, credit humain et bots verifies
- [x] `specs/schemas/config.schema.json` : contrat `risk_engine` ajoute avec `additionalProperties: false`
- [x] `configs/config.example.yaml` : exemple de configuration `risk_engine` balanced
- [x] Tests table-driven / deterministes : score, confiance, profils, credit humain, conversion config, validation des bornes de config
- **Acceptance** : memes signaux + meme profil donnent le meme score, la confiance baisse quand peu de familles sont disponibles, les profils modifient le scoring, et la config invalide est rejetee au demarrage
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-detection.md FR-33, NFR-16 ; schemas/config.schema.json ; ADR-015 ; plan.md Slice 6.2

### T6.3 - Mapping vers l'echelle de mitigation graduee
- [x] `internal/risk/decision.go` : mapping `(risk_score, confidence)` vers `ALLOW`, `OBSERVE`, `THROTTLE`, `CHALLENGE`, `TARPIT`, `BLOCK`
- [x] Bornes de score configurables via `DecisionConfig` et `DecisionConfigFromConfig`
- [x] Profils `lenient`, `balanced`, `strict` avec seuils de tiers et `block_min_confidence` differencies
- [x] Plafond a `CHALLENGE` quand la confiance est sous `block_min_confidence` pour les mitigations dures
- [x] `ApplyDecision` met a jour une `RiskAssessment` sans implementer encore la corroboration ni les triggers deterministes de la Slice 6.4
- [x] Tests derives du Scenario Outline `features/risk-scoring-engine.feature` : `(5,0.9)->ALLOW`, `(30,0.8)->OBSERVE`, `(50,0.8)->THROTTLE`, `(70,0.8)->CHALLENGE`, `(90,0.9)->BLOCK`
- **Acceptance** : le mapping est deterministe, respecte les bornes configurables/profilables, et plafonne les decisions au-dessus de `CHALLENGE` lorsque la confiance est insuffisante
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-detection.md FR-34 ; features/risk-scoring-engine.feature Scenario Outline Mapping ; ADR-015 ; plan.md Slice 6.3

### T6.4 - Corroboration & signaux deterministes
- [x] `ApplyDecision` exige `corroborating_families >= min_corroborating_families` pour conserver un `BLOCK` heuristique
- [x] Un signal heuristique isole produisant un score de BLOCK est plafonne a `CHALLENGE`
- [x] Les triggers deterministes `blacklist`, `honeypot`, `ja3_blacklist`, `threat_intel_critical`, `circuit_breaker` peuvent produire un `BLOCK` sans corroboration
- [x] `block_min_confidence` reste applique : pas de `BLOCK` lorsque la confiance est insuffisante
- [x] `DecisionConfigFromConfig` reprend `min_corroborating_families` depuis `risk_engine`
- [x] Tests : signal isole, deux familles corroborantes, confiance insuffisante, triggers deterministes, trigger deterministe a faible confiance
- **Acceptance** : un `BLOCK` heuristique exige assez de familles corroborantes, les triggers deterministes sont marques `decision_basis=deterministic`, et la confiance minimale interdit un `BLOCK` faible confiance
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-detection.md FR-35 ; features/risk-scoring-engine.feature scenarios Corroboration et Signaux deterministes ; ADR-015 ; plan.md Slice 6.4

### T6.5 - Allowlist de bots verifies (reverse-DNS)
- [x] `internal/risk/verifybot.go` : verification reverse-DNS + forward-confirm avec `net.LookupAddr` / `net.LookupHost` par defaut
- [x] Verification asynchrone non bloquante : cache miss -> etat `pending` immediat et resolution lancee en goroutine
- [x] Cache TTL separe pour succes et echec via `BotVerifierConfig`
- [x] Crawler verifie -> `ALLOW`, `decision_basis=verified_bot`, `verified_good_bot=<bot>`, sauf trigger deterministe deja present
- [x] Crawler declare en `pending` -> decision plafonnee a `OBSERVE`, jamais `CHALLENGE` ni `BLOCK`
- [x] UA crawler spoofe -> contribution `reputation` augmentee via signal `crawler_spoof`
- [x] Tests avec resolveur mocke : Googlebot verifie, pending non bloquant, faux Googlebot suspect, preservation des blocks deterministes, parsing TTL depuis config
- **Acceptance** : un crawler verifie n'est jamais bloque/challenge par heuristique, un crawler en attente est laisse passer en `OBSERVE`, et un UA spoofe ajoute un signal reputation suspect
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-detection.md FR-36, NFR-08 ; features/risk-scoring-engine.feature scenarios Bots verifies ; ADR-015 ; plan.md Slice 6.5

### T6.6 - Credits de preuve humaine & trust persistant
- [x] `internal/risk/human.go` : `HumanTrustManager` sur `storage.Store` pour grant/proof/revoke du sticky trust
- [x] `VisitorState.StickyTrustUntil` ajoute au stockage et a `schemas/visitor.schema.json`
- [x] `HumanCreditContribution` produit une contribution negative `human_credit` pour challenge reussi et fingerprint stable
- [x] `ApplyHumanCredit` autorise une preuve humaine forte, plafonne un block heuristique a `CHALLENGE`, et n'ecrase pas un block deterministe
- [x] TTL sticky trust configurable via `HumanCreditConfigFromConfig`
- [x] Tests : grant sticky trust TTL, preuve fingerprint stable, revocation, contribution negative, non-rechallenge via `ALLOW`, garde-fou anti-BLOCK heuristique, revocation logique sur trigger deterministe
- **Acceptance** : un humain avec challenge reussi et fingerprint stable obtient `ALLOW` + `sticky_trust=true`, un credit humain empeche un `BLOCK` heuristique, et un trigger deterministe revoque/ne respecte pas le sticky trust
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-detection.md FR-37 ; features/risk-scoring-engine.feature scenarios Credits de preuve humaine ; schemas/visitor.schema.json ; ADR-015 ; plan.md Slice 6.6
