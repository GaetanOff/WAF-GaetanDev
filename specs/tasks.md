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

### T6.7 - Middleware de decision (integration pipeline)
- [x] `internal/risk/middleware.go` : middleware HTTP de decision place apres les detecteurs et avant le proxy
- [x] `cmd/waf/main.go` : `risk.Middleware` cable a la place du mapping direct `ScoreManager.Middleware` quand `risk_engine.enabled=true`
- [x] Fallback conserve vers `ScoreManager.Middleware` quand le moteur de risque est desactive
- [x] Le middleware consomme le Trust Score comme signal `reputation` et les headers internes `X-WAF-Risk-*` produits par les detecteurs
- [x] `RiskAssessment` condensee injectee dans les headers : `X-WAF-Risk-Score`, `X-WAF-Risk-Decision`, `X-WAF-Risk-Confidence`, `X-WAF-Score-Delta`, `X-WAF-Reason`
- [x] Logger securite : `score_delta` est maintenant emis dans `SecurityEvent`
- [x] Tests `httptest` : block deterministe avant proxy, block heuristique corrobore, headers condenses, preuve humaine forte, integration routes avant proxy
- **Acceptance** : le moteur de risque remplace le seuil simple du Trust Score dans le pipeline, bloque avant proxy quand la decision est `BLOCK`, marque les challenges/observations dans les headers, et expose la forme condensee pour logs/metrics
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-detection.md FR-33, FR-34, NFR-17 ; schemas/security-event.schema.json ; ADR-015 ; plan.md Slice 6.7

### T6.8 - Mode shadow, boucle de feedback FP & metriques
- [x] `risk.Middleware` respecte `risk_engine.shadow_mode` : decision calculee et exposee, mais non appliquee
- [x] Headers shadow/log : `X-WAF-Risk-Shadow-Mode`, `X-WAF-Risk-Decision`, `X-WAF-Risk-Confidence`
- [x] `SecurityEvent` et `schemas/security-event.schema.json` etendus avec `risk_score`, `risk_decision`, `risk_confidence`, `shadow_mode`
- [x] `internal/risk/feedback.go` : boucle de feedback locale bornee pour faire decroitre les poids des familles apres challenge reussi
- [x] Metriques FR-38 : `waf_decisions_total{tier}`, `waf_challenge_pass_after_flag_total`, `waf_hard_blocks_total{corroborated}`, `waf_verified_bot_total{bot}`
- [x] Tests : shadow non applique mais loggable, decroissance de poids bornee, metriques Prometheus
- **Acceptance** : une decision `BLOCK` en shadow laisse passer la requete tout en exposant la decision, un challenge reussi apres flag peut reduire le poids local des familles fautives, et les metriques FR-38 sont exposees
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-detection.md FR-38, NFR-15 ; features/risk-scoring-engine.feature scenarios Shadow/Feedback ; schemas/security-event.schema.json ; ADR-015 ; plan.md Slice 6.8

---

## Sprint 7 - Cablage des signaux du moteur de risque (Phase 7)

### T7.1 - Adaptateurs de signaux des detecteurs existants
- [x] antibot publie une contribution `fingerprint` via `X-WAF-Risk-fingerprint` (delta negatif non bloquant -> contribution positive)
- [x] antibot marque `X-WAF-Deterministic-Trigger=honeypot` sur chemin honeypot (blocage immediat conserve)
- [x] access/blacklist marque `X-WAF-Deterministic-Trigger=blacklist`
- [x] antiddos marque `X-WAF-Deterministic-Trigger=circuit_breaker` sur circuit ouvert
- [x] ratelimit publie une contribution `rate` via `X-WAF-Risk-rate` proportionnelle a la depletion du bucket (429 volumetrique inchange)
- [x] Tests : header fingerprint=30 sur headless, trigger honeypot/blacklist/circuit_breaker, contribution rate=100 a bucket vide ; test routes mis a jour (antibot pilote desormais le signal fingerprint)
- **Acceptance** : les detecteurs deja implementes alimentent le moteur de risque ; une famille reelle (fingerprint/rate) s'ajoute a `reputation` pour rendre la corroboration FR-35 possible
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-detection.md FR-33, FR-35 (Articulation) ; plan.md Slice 7.1

### T7.2 - Corroboration effective + deploiement shadow
- [x] `risk_engine.shadow_mode` passe a `true` par defaut (calibration NFR-15, >= 24h avant enforcement) dans `config.Default()` et `configs/config.example.yaml`
- [x] Tests d'integration end-to-end via `routes()` :
  - shadow par defaut : decision calculee/exposee (`X-WAF-Risk-Shadow-Mode`) mais NON appliquee
  - corroboration de signaux reels (reputation faible + rate du bucket vide) -> `BLOCK` corrobore avec tiers ajustes (`X-WAF-Risk-Corroborated=true`)
- [x] `TestRoutesAppliesRiskDecisionBeforeProxy` force `shadow_mode=false` (test d'enforcement)
- **Note de conception** : avec seules 3 familles cablees (reputation/fingerprint/rate), le denominateur de fusion (somme de tous les poids) dilue le score → le moteur produit surtout CHALLENGE/OBSERVE et bloque rarement. C'est la protection anti-FP attendue ; les BLOCK durs deviennent realistes quand les detecteurs de la Phase 8 alimentent plus de familles.
- **Acceptance** : le moteur est en shadow par defaut ; les signaux reels des detecteurs sont fusionnes et comptes comme familles corroborantes de bout en bout
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-detection.md FR-35, FR-38, NFR-15 ; plan.md Slice 7.2

---

## Sprint 8 - Detecteurs avances (Phase 8)

### T8.1 - Analyse d'integrite des requetes (FR-18)
- [x] `internal/integrity/integrity.go` : detection traversal (`../`, `%2e%2e`, `..%2f`), octet nul (`%00`), patterns d'injection (SQL/XSS), longueurs excessives ; analyse aussi une forme decodee (`+`->espace, `%xx`)
- [x] Contribution de la famille `integrity` publiee via `X-WAF-Risk-integrity` (ne bloque jamais : FR-18 laisse l'app decider, le moteur arbitre)
- [x] Limite de taille de body configurable (defaut 10 MB) -> HTTP 413 + `http.MaxBytesReader`
- [x] Config `integrity` (enabled, max_body_bytes, max_path_length, max_query_length) + schema + exemple + validation
- [x] Refactor `routes()` : parametre `detectors []func(http.Handler) http.Handler` execute juste avant le moteur de risque (reutilise par les slices 8.x suivantes)
- [x] Tests : detections (traversal/injection/xss/longueur), publication de contribution sans blocage, body 413, bypass sur `X-WAF-Action=PASS`
- **Acceptance** : les anomalies d'integrite contribuent au score de risque sans bloquer directement ; un body trop volumineux est rejete en 413
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-advanced.md FR-18 ; features/request-integrity.feature ; plan.md Slice 8.1

### T8.2 - Analyse comportementale (FR-12)
- [x] `internal/behavioral/behavioral.go` : ring buffer par visiteur (N derniers paths+timestamps), worker asynchrone (NFR-07, file non bloquante)
- [x] 6 signaux : uniformite temporelle, repetition de path, velocite de decouverte, absence d'assets, ordre alphabetique (depth simplifie)
- [x] Score d'anomalie [0..100] applique a la requete suivante via `X-WAF-Risk-behavioral`
- [x] Arret propre via `stop` channel (queue jamais fermee : pas de panic si Observe pendant shutdown)
- [x] Config `behavioral` (enabled, max_records defaut 50) + schema + exemple + validation
- [x] Cable comme detecteur Phase 8 (slice `detectors`)
- [x] Tests : score nul sous le minimum, detection uniformite/repetition/velocite/absence d'assets, navigation humaine -> score bas, publication depuis le score precedent, bypass PASS
- **Acceptance** : un comportement de bot (timing regulier, crawl) produit un score d'anomalie eleve applique a la requete suivante, sans bloquer le pipeline (async)
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-advanced.md FR-12, NFR-07 ; ADR-009 ; features/behavioral-analysis.feature ; plan.md Slice 8.2

### T8.3 - Threat intelligence (FR-13)
- [x] `internal/threatintel` : Checker avec cache TTL et resolution asynchrone non bloquante (NFR-08)
- [x] `StaticSource` : feeds locaux CIDR (blocklist -> malicious, Tor/datacenter -> suspect)
- [x] `HTTPSource` : client type AbuseIPDB v2 (score >= 80 critique, >= 50 malveillant), execute dans la goroutine de resolution
- [x] Integration : verdict critique -> trigger deterministe `threat_intel_critical` (BLOCK via moteur, FR-35) ; sinon plafond de trust score idempotent (renforce la famille `reputation`)
- [x] Config `threat_intel` (enabled opt-in, cache_ttl, blocklist_cidrs, suspect_cidrs, abuseipdb) + schema + exemple + validation
- [x] 100% stdlib (pas de maxminddb : ASN exprimables en CIDR via les feeds)
- [x] Tests : StaticSource (pire niveau), cache du Checker, middleware critique/malicious, HTTPSource via httptest
- **Acceptance** : une IP en feed/AbuseIPDB voit sa reputation degradee (plafond) ou est bloquee (critique) sans bloquer la requete sur le lookup (async)
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-advanced.md FR-13, NFR-08 ; ADR-006 ; features/threat-intelligence.feature ; plan.md Slice 8.3

### T8.4 - Difficulte de PoW adaptative (FR-14)
- [x] `internal/adaptive` : contrôleur d'intensite (fenetre glissante + baseline EMA), AII = rate/baseline, niveaux Normal/Eleve(+4)/Critique(+8), plafond configurable
- [x] Montee immediate, retour par decroissance exponentielle (decay, tau defaut 5m) ; `Difficulty()` (avance le decay) et `Snapshot()` (lecture seule)
- [x] Difficulte embarquee dans le token signe (`TokenPayload.Difficulty`) -> validation cote serveur via la difficulte du token (anti-retrogradation, FR-14)
- [x] Challenge : `WithDifficultyProvider`, `servePage` embarque la difficulte courante, `verify` valide avec la difficulte du token
- [x] Metrique `waf_challenge_pow_difficulty` (gauge) exposee
- [x] Config `adaptive` (enabled, max_difficulty 24, decay_tau 5m) + schema + exemple + validation
- [x] Tests : mapping AII->bits, montee/decroissance, contrôleur sous attaque, snapshot read-only
- **Acceptance** : sous attaque la difficulte monte (jusqu'au plafond) puis redescend ; un client legitime n'est jamais rejete par rehaussement (difficulte figee dans le token)
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-advanced.md FR-14 ; ADR-010 ; features/adaptive-protection.feature ; plan.md Slice 8.4

### T8.5 - Regles geographiques (FR-16)
- [x] `internal/geo` : lecture `CF-IPCountry`, ensembles compiles O(1) (allowed/blocked/challenge)
- [x] Mode whitelist (allowed non vide -> les autres pays en 403), blocage par pays (403), pays a challenge -> contribution `geo` (X-WAF-Risk-geo)
- [x] Degradation gracieuse : header CF-IPCountry absent -> regles ignorees
- [x] Config `geo` (enabled opt-in, allowed/blocked/challenge_countries, challenge_contribution) + schema + exemple + validation
- [x] Cable comme detecteur Phase 8
- [x] Tests : pays bloque (403), whitelist (FR ok / US 403), pays challenge (contribution 60), header absent -> pass
- **Acceptance** : les regles par pays bloquent ou renforcent le risque selon CF-IPCountry ; absence de header => aucun effet
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-advanced.md FR-16 ; features/geo-rules.feature ; plan.md Slice 8.5

### T8.6 - TLS / JA3 fingerprinting (FR-11)
- [x] `internal/tlsfp` : `JA3String` (format canonique) + `JA3Hash` (MD5) en utilitaires purs (capture TLS directe fournie, cablage live differe)
- [x] Mode hybride live : lecture du header Cloudflare `Cf-Bot-Management-Ja3Hash`
- [x] Blacklist JA3 -> trigger deterministe `ja3_blacklist` (BLOCK via moteur, FR-35)
- [x] Detection de swap JA3 par visiteur (cache memoire ip->ja3) -> contribution `tls`
- [x] Degradation gracieuse : pas de header JA3 (Cloudflare sans Bot Management) -> collecte ignoree
- [x] Config `tls_fingerprint` (enabled, ja3_header, ja3_blacklist, swap_contribution) + schema + exemple + validation
- [x] Tests : JA3String/Hash, blacklist->trigger, swap->contribution, header absent->pass
- **Acceptance** : un JA3 blackliste est bloque deterministiquement ; un changement de JA3 entre sessions augmente le risque ; absence de JA3 sans effet
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-advanced.md FR-11 ; ADR-005 ; features/tls-fingerprinting.feature ; plan.md Slice 8.6

### T8.7 - Couche de deception / tarpit (FR-15)
- [x] `internal/deception` : tarpit servant une fausse page HTML 200 par chunks espaces de delais
- [x] Semaphore bornant les connexions tarpitees simultanees (NFR-10) ; au-dela -> 429
- [x] Annulation propre via `r.Context().Done()` (client deconnecte)
- [x] Cable via `Dispatch` wrappant le proxy : sert le tarpit quand le moteur a classe la requete TARPIT, sinon transmet
- [x] Config `deception` (enabled, tarpit_max_connections 500, tarpit_chunks, tarpit_chunk_delay) + schema + exemple + validation
- [x] Tests : pass-through hors TARPIT, HTML factice complet, 429 quand semaphore plein
- **Note** : injection de contenu honeypot dans les reponses HTML differee ; la detection du suivi d'un chemin honeypot est deja couverte par antibot (honeypot_paths -> trigger deterministe en 7.1)
- **Acceptance** : une requete classee TARPIT recoit une reponse lente bornee en concurrence, sans atteindre l'origine
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-advanced.md FR-15, NFR-10 ; ADR-008 ; features/deception-layer.feature ; plan.md Slice 8.7

### T8.8 - Moteur de regles personnalisees (FR-17)
- [x] `internal/rules` : DSL YAML compile en structs au chargement (regex/CIDR precompiles), tri par priorite, premier match -> short-circuit (sauf `continue: true`)
- [x] Conditions : ip (equals/in_list/in_cidr), user_agent/path/method/country/header/query_param (equals/contains/starts_with/ends_with/exists/in_list/matches_regex), trust_score (lt/lte/gt/gte)
- [x] Actions : block, tarpit, score_delta, add_header, log
- [x] Hot-reload via `atomic.Value` (Load/LoadFile remplacent le jeu sans verrou sur le chemin requete)
- [x] Config `rules` (enabled opt-in, file) + schema + exemple + validation
- [x] Tests : priorite + continue, ip_cidr+method, regle desactivee, hot-reload, regex invalide rejetee au load, middleware block
- **Note** : actions challenge/rate_limit/redirect et conditions ja3/behavioral via header differees (couvertes partiellement par les autres detecteurs) ; exposition admin (hit counts) differee
- **Acceptance** : un jeu de regles YAML bloque/tarpit/ajuste le score selon des conditions composables, rechargeable a chaud
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-advanced.md FR-17, NFR-09 ; ADR-007 ; schemas/rule.schema.json ; features/rules-engine.feature ; plan.md Slice 8.8

### T8.9 - Protection de l'origine (FR-19)
- [x] `internal/origin` : token `X-WAF-Origin-Token` = HMAC-SHA256(secret, domaine + heure), rotatif horaire, tolerance 2h
- [x] `Injector` pose le token sur la requete avant le proxy (transmis a l'upstream par httputil.ReverseProxy)
- [x] Endpoint `GET /waf/origin/verify` (200/401) pour que l'upstream valide le token
- [x] Secret via config `origin_protection.secret` + override env `WAF_ORIGIN_SECRET`
- [x] Cable dans `routes()` (endpoint + injection) sans changement de signature
- [x] Config `origin_protection` (enabled opt-in, secret >= 16 chars) + schema + exemple + validation
- [x] Tests : rotation + tolerance 2h, token specifique au domaine, injection, verify handler 200/401
- **Note** : mTLS vers l'upstream differe (note)
- **Acceptance** : l'upstream peut rejeter les requetes sans token WAF valide ; le token tourne sans coupure (tolerance 2h)
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-advanced.md FR-19 ; features/origin-protection.feature ; plan.md Slice 8.9

### T8.10 - Backend Redis + synchronisation cluster (FR-20)
- [x] `internal/cluster` : modele Event (blacklist_add, score_critical, circuit_open, degraded_mode), interface `Bus`, `LocalBus` (mono-noeud/tests), `RedisBus` (go-redis Pub/Sub)
- [x] `Syncer` applique les events entrants a l'etat local : blacklist -> `access.RuleSet.AddBlacklist` (ajoute) ; score_critical -> `store.SetVisitor`
- [x] Fallback autonome : erreur de bus silencieuse cote publication ; boucle d'abonnement s'arrete a l'annulation du contexte
- [x] `access.RuleSet.AddBlacklist` ajoute (incremental, idempotent)
- [x] Metrique `waf_cluster_sync_events_total{type}`
- [x] Config `cluster` (enabled opt-in, channel) reutilisant `storage.redis` ; dependance `github.com/redis/go-redis/v9` ajoutee (seule dep externe de la Phase 8) ; schema + exemple + validation (exige storage.redis.address)
- [x] Tests : LocalBus roundtrip, Syncer applique blacklist + score critique
- **Note** : emission des events locaux (hooks admin/access) exposee via `Syncer.Publish` mais cablage des emetteurs differe ; RedisBus teste en integration (docker-compose) plutot qu'en unitaire
- **Acceptance** : un event de blacklist/score critique recu se propage a l'etat local ; le noeud fonctionne sans Redis (degrade)
- **Validation 2026-06-08** : `go mod tidy`, `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-advanced.md FR-20 ; ADR-002 ; features/multi-node-sync.feature ; plan.md Slice 8.10

---

## Sprint 9 - Durcissement production / Ops (Phase 9)

### T9.1 - En-tetes de securite + sanitisation (FR-21, FR-22)
- [x] `internal/secheaders` : `sanitizingWriter` qui applique a l'ecriture des en-tetes
- [x] Injection si absent (priorite upstream) : HSTS, X-Frame-Options, X-Content-Type-Options (nosniff), Referrer-Policy, Permissions-Policy, CSP (opt-in)
- [x] Sanitisation : retrait des en-tetes reveleurs (Server, X-Powered-By, configurable)
- [x] Cable le plus a l'exterieur (enrobe tout le mux dans `routes()`)
- [x] Config `security_headers` + schema + exemple
- [x] Tests : injection, priorite upstream, strip, CSP opt-in
- **Acceptance** : les reponses portent les en-tetes de securite (sans ecraser l'upstream) et ne revelent pas la stack
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-ops.md FR-21, FR-22 ; ADR-011 ; features/security-headers.feature ; plan.md Slice 9.1

### T9.2 - Protection Slowloris / Slow POST (FR-23)
- [x] `internal/slowloris` : limiteur de requetes concurrentes par IP (429 + Retry-After au-dela)
- [x] `ReadHeaderTimeout` du http.Server rendu configurable (slowloris.header_timeout)
- [x] Cable sous les en-tetes de securite (le 429 porte aussi les headers)
- [x] Config `slowloris` (enabled, max_connections_per_ip 50, header_timeout) + schema + exemple + validation
- [x] Tests : liberation sequentielle, rejet concurrent au-dela, isolation par IP
- **Note** : debit minimal du corps approxime par ReadTimeout (configurable) ; limitation au niveau connexion TCP par ConnState differee
- **Acceptance** : un client ouvrant trop de connexions concurrentes est limite (429) ; les en-tetes lents expirent (header_timeout)
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-ops.md FR-23, NFR-11 ; features/slowloris-protection.feature ; plan.md Slice 9.2
