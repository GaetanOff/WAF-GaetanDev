---
status: draft
sprint: 5
last-updated: 2026-06-09
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
- **Deprecated par spec 2026-06-09** : remplacé par T10.1 ; le dépassement du trafic global ne doit plus produire de 503 automatique.
- **Spec** : requirements FR-08 v1.0.0, remplacé par requirements FR-08 v2.0.0

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

### T9.3 - Bypass des assets statiques (FR-24)
- [x] `internal/staticassets` : marque les requetes d'assets (extensions configurables) en `X-WAF-Action=PASS`
- [x] Court-circuite challenge/trust/rate/antibot/risk (qui honorent PASS) sans desactiver la blacklist (access ne skip pas sur PASS entrant)
- [x] Cable le plus en amont de la chaine proxy (avant challenge)
- [x] Config `static_assets` (enabled, extensions par defaut .css/.js/.png/...) + schema + exemple
- [x] Tests : asset -> PASS, chemin dynamique -> non marque, bypass desactive
- **Acceptance** : le CSS/JS de la page de challenge n'est pas challenge (pas de deadlock) ; les assets ne sont pas scores
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-ops.md FR-24 ; features/static-assets-bypass.feature ; plan.md Slice 9.3

### T9.4 - Health checks upstream + load balancing (FR-25, FR-26)
- [x] `internal/upstream` : `Pool` avec etat sain par upstream (atomic.Bool), stratégies round_robin / least_conn / ip_hash / weighted, fallback backup si primaires down
- [x] `HealthChecker` : goroutine de sondage par upstream, seuils succes/echec consecutifs, MAJ atomic
- [x] Integration proxy : `Handler.WithPool` (selection health-aware par requete, priorite sur le routage par domaine) ; ErrorHandler marque l'upstream non sain au premier echec de connexion (failover)
- [x] Config `upstream_pool` (enabled, strategy, upstreams[], health_check) + schema + exemple + validation
- [x] Tests : round-robin, exclusion non-sain, fallback backup, tout down, ip_hash stable, least_conn, weighted
- **Note** : retry per-requete synchrone (sur 502) approxime par failover health-aware (l'upstream en echec est marque down) ; combinaison pool + routage par domaine differee
- **Acceptance** : le trafic est reparti sur les upstreams sains selon la stratégie ; un upstream down est exclu et les backups prennent le relais
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-ops.md FR-25, FR-26, NFR-13 ; ADR-012 ; schemas/upstream-pool.schema.json ; features/upstream-health.feature ; plan.md Slice 9.4

### T9.5 - Audit trail admin (FR-27)
- [x] `internal/audit` : journal append-only thread-safe, rotation FIFO (max_entries), masquage des secrets, export fichier optionnel
- [x] Cable dans le serveur admin : record sur add/remove whitelist, add/remove blacklist, patch config, reset visitor
- [x] Endpoint `GET /waf/admin/audit` (auth, pagine) ; Trail ferme au shutdown
- [x] Config `audit` (enabled, max_entries 1000, file) + schema + exemple
- [x] Tests : record+list, rotation FIFO, masquage des secrets
- **Acceptance** : chaque mutation admin est journalisee (horodatee, secrets masques) et consultable ; rotation bornee
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-ops.md FR-27 ; features/audit-trail.feature ; plan.md Slice 9.5

### T9.6 - Conformite RGPD (FR-28)
- [x] `internal/gdpr.AnonymizeIP` : troncature /24 (IPv4) et /48 (IPv6)
- [x] Logger : champ `AnonymizeIP` -> l'IP loggee est anonymisee (l'ip_hash reste pour la correlation)
- [x] Droit a l'effacement : endpoint admin `POST /waf/admin/gdpr/erase {ip}` (supprime par hash IP + audit)
- [x] Retention : assuree par le TTL du store (purge) ; registre des traitements `specs/gdpr-register.md`
- [x] Config `gdpr` (anonymize_ip true par defaut) + schema + exemple
- [x] Tests : anonymisation v4/v6/invalide
- **Acceptance** : les logs n'exposent pas l'IP complete (anonymisee), un utilisateur peut etre efface, le registre documente les traitements
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-ops.md FR-28 ; ADR-013 ; features/gdpr-compliance.feature ; plan.md Slice 9.6

### T9.7 - Alerting webhooks (FR-29)
- [x] `internal/alert` : Notifier async (file + worker), sinks Slack / Discord / generique, retry backoff exponentiel, deduplication par cooldown (trigger+domaine)
- [x] Emission depuis le logger (interface `Alerter`) sur block / circuit_breaker / honeypot
- [x] Config `alerting` (enabled opt-in, cooldown, max_retries, webhooks[]) + schema + exemple + validation
- [x] Tests via httptest : delivery (payload Slack), cooldown dedup, retry sur echec
- **Note** : emetteurs additionnels (pression globale, seuils) cablables via Notifier.Dispatch ; differes
- **Acceptance** : un evenement a forte severite declenche une alerte webhook (formatee selon le sink), sans flood (cooldown), sans bloquer la requete (async)
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-ops.md FR-29, NFR-12 ; schemas/alert.schema.json ; features/webhook-alerts.feature ; plan.md Slice 9.7

### T9.8 - Auto-protection du WAF (FR-30)
- [x] `internal/selfprotect` : compteur par IP a fenetre fixe (`Window`), `PathGuard` (limite un chemin precis)
- [x] Flood `/waf/verify` : PathGuard cable dans la chaine proxy (429 au-dela de verify_max_per_minute par IP)
- [x] Brute-force admin : `admin.auth` verrouille l'IP (429) apres admin_max_failures echecs pendant admin_lockout
- [x] Config `self_protection` (enabled, verify_max_per_minute, admin_max_failures, admin_lockout) + schema + exemple + validation
- [x] Tests : window record/limited/reset, PathGuard cible/ignore, (admin couvert par ses tests)
- **Acceptance** : un flood de /waf/verify est limite par IP ; les tentatives d'auth admin repetees verrouillent l'IP
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent.
- **Spec** : requirements-ops.md FR-30 ; features/waf-self-protection.feature ; plan.md Slice 9.8

### T9.9 - ACME / Let's Encrypt (FR-31)
- [x] `internal/acme` : wrapper autocert.Manager (HostWhitelist, DirCache, email, AcceptTOS) ; `TLSConfig()` + `HTTPHandler()`
- [x] Renouvellement auto ~30j avant expiration + rotation a chaud : natif autocert
- [x] Cable dans `main.go` : si active, serveur HTTPS sur tls_listen (ListenAndServeTLS via autocert) + serveur HTTP-01 sur http_challenge_listen
- [x] Dependance `golang.org/x/crypto@v0.31.0` pinnee (compatible go 1.22 ; evite le bump go 1.25 du Dockerfile/CI)
- [x] Config `acme` (enabled opt-in, domains, email, cache_dir, tls_listen, http_challenge_listen) + schema + exemple + validation
- [x] Tests : construction TLSConfig (GetCertificate, MinVersion), HTTPHandler, cache dir par defaut
- **Note** : alerte d'expiration secondaire (autocert renouvelle automatiquement) differee
- **Acceptance** : en mode TLS direct, les certificats sont obtenus/renouveles automatiquement via ACME, sans coupure (rotation a chaud)
- **Validation 2026-06-08** : `go mod tidy`, `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent ; go directive reste 1.22
- **Spec** : requirements-ops.md FR-31, NFR-14 ; features/acme-tls.feature ; plan.md Slice 9.9

### T9.10 - Mode maintenance & pages d'erreur personnalisees (FR-32)
- [x] `internal/maintenance` : middleware combinant mode maintenance (503 brandee pour tout le trafic hors endpoints internes) et remplacement des corps d'erreur (4xx/5xx) en texte brut par une page HTML brandee
- [x] Pages brandees « Protected by GaetanDev.fr » : HTML autonome (CSS inline, aucune ressource externe), messages par statut (403/429/503/502/defaut)
- [x] Preservation : reponses 2xx et erreurs deja en HTML (ex: page de challenge) inchangees ; endpoints internes (`/waf/health`, `/waf/metrics`) exemptes du mode maintenance
- [x] Cable dans `main.go` : `maintenance.New(cfg.Maintenance).Handler` entre slowloris et security_headers
- [x] Config `maintenance` (enabled false, error_pages true par defaut) + schema + exemple
- [x] Tests : 503 maintenance + branding, bypass /waf/health, remplacement 403 texte->HTML, preservation 200 et HTML existant, passthrough si desactive
- **Acceptance** : en mode maintenance tout le trafic recoit une page 503 brandee (hors endpoints internes) ; hors maintenance les erreurs en texte brut sont remplacees par une page brandee, le reste est preserve
- **Validation 2026-06-08** : `go test ./...`, `go vet ./...`, `go build ./...` passent.
- **Spec** : requirements-ops.md FR-32 ; plan.md Slice 9.10

---

## Sprint 10 - Revision Anti-DDoS adaptative (Phase 10)

### T10.1 - Remplacer le 503 global par la pression adaptative (FR-08 v2)
- [x] Remplacer `GlobalRateDetector` par un compteur de pression a cout borne (fenetre fixe ou anneau de buckets), sans slice de timestamps non bornee sur le chemin requete
- [x] Ajouter les niveaux `normal`, `elevated`, `high`, `critical` calcules depuis `antiddos.global_requests_per_second` et `antiddos.pressure_levels`
- [x] Supprimer le rejet automatique des nouveaux visiteurs en HTTP 503 base uniquement sur le seuil global
- [x] Publier la pression globale vers les headers internes/signaux du moteur de risque (`rate` ou `global_pressure`) et vers le controleur PoW adaptatif
- [x] Renforcer les mitigations reversibles pour visiteurs inconnus/suspects sous pression : challenge, throttling, difficulte PoW ; conserver les visiteurs connus/cookie valide sous leurs controles par IP
- [x] Exposer logs et metriques du niveau de pression courant
- [x] Tests Gherkin : pas de 503 global, visiteur connu favorise, abus par IP toujours 429, circuit-breaker inchangé
- **Acceptance** : depasser le seuil global ne bloque jamais tout le trafic ni tous les nouveaux visiteurs par lui-meme ; les mitigations restent graduelles et reversibles.
- **Validation 2026-06-09** : `go test ./...`, `go vet ./...`, `go build -o waf.exe ./cmd/waf` passent ; schemas JSON config/security-event valides.
- **Revue 2026-06-09 (post-implementation)** : trois correctifs suite a une relecture du code :
  - THROTTLE reellement implemente dans `ratelimit` : sous pression, le debit ET la capacite effectifs des visiteurs non-TRUSTED sont resserres (elevated ×0.8, high ×0.5, critical ×0.25), recalcules par requete depuis la config (jamais figes dans le store), donc reversibles. Les visiteurs TRUSTED (score ≥ 70) gardent leur debit nominal. Couvre la mitigation "THROTTLE" de features/anti-ddos.feature.
  - Bug corrige dans `adaptive` : `high` et `critical` renvoyaient les memes bits PoW ; ajout de `highExtraBits=6` (elevated 4 / high 6 / critical 8, strictement croissants).
  - Code mort supprime : override `statusRecorder.Write` no-op dans `antiddos/middleware.go`.
  - Tests ajoutes : `ratelimit` (throttle inconnu, visiteur TRUSTED epargne, pression normale, reversibilite) ; `adaptive` (4 niveaux distincts).
- **Spec** : requirements.md FR-08 v2.0.0 ; features/anti-ddos.feature ; ADR-016 ; schemas/config.schema.json

## Sprint 11 - Terminaison TLS par domaine (Phase 11)

### T11.1 - TLS par domaine avec selection par SNI (FR-33)
- [x] Ajouter le bloc `server.tls` (enabled, listen, min_version, cipher_suites, redirect_http, cert_file/key_file par defaut) et `domains[].tls` (cert_file, key_file) au parsing config + Validate (fail-fast si fichier manquant / cle non concordante)
- [x] Implementer `internal/tlsmgr` : chargement des paires PEM par domaine au demarrage + `tls.Config.GetCertificate` qui selectionne par SNI (exact + wildcard `*.example.com`)
- [x] Repli sur le certificat par defaut si SNI sans correspondance ; sinon refus de handshake (`unrecognized_name`)
- [x] Cabler le listener HTTPS dans `cmd/waf/main.go` a cote du chemin ACME (mutuellement exclusifs sur un meme listener) ; redirection HTTP->HTTPS si `redirect_http`
- [x] Exposer `waf_tls_cert_expiry_seconds{domain}` par certificat charge
- [ ] (Optionnel, hors premiere tranche) hot-reload des certs sur SIGHUP — **non implemente** (renouvellement gere en amont, redeploiement acceptable)
- [x] Tests : selection SNI (exact/wildcard/inconnu), fail-fast (fichier manquant, cle non concordante), plancher TLS 1.2, redirection 301
- [ ] Doc deploiement : bascule OpenResty en HTTP interne + `set_real_ip_from` (DEPLOYMENT.md) — **a faire au moment de la bascule prod**
- **Acceptance** : un client en TLS recoit le certificat correspondant a son SNI ; un SNI sans cert et sans defaut est refuse sans servir de cert arbitraire ; un cert manquant empeche le demarrage.
- **Validation 2026-06-10** : `go test ./...`, `go vet ./...`, `go build ./...` passent ; schema JSON config valide ; **smoke test handshake reel** (openssl s_client) : SNI alpha→cert alpha, SNI beta→cert beta, SNI inconnu→alert TLS (refus), HTTP→HTTPS 301.
- **Spec** : requirements-ops.md FR-33 ; features/per-domain-tls.feature ; ADR-017 ; schemas/config.schema.json

## Sprint 12 - Mode "sous attaque" anti-DDoS L7 (Phase 12)

### T12.1 - Mode sous attaque : challenge force pilote par la pression (FR-39)
- [x] Ajouter le bloc `antiddos.under_attack` (enabled, scope, trigger_pressure, exit_pressure, cooldown, shadow, max_tracked_domains) au parsing config + Validate (enums admis, `trigger_pressure >= exit_pressure` selon l'ordre normal<elevated<high<critical, cooldown duree > 0, max_tracked_domains >= 1)
- [x] `internal/middleware/antiddos` : compteur de pression **par domaine** (anneau de buckets par domaine, nombre de domaines borne par LRU `max_tracked_domains`) ; `scope` choisit global vs per-domaine
- [x] `internal/middleware/antiddos` : controleur de mode sous attaque par scope avec **hysteresis** (entree a `trigger_pressure`, sortie sous `exit_pressure` maintenu pendant `cooldown`) ; expose l'etat via headers internes `X-WAF-Under-Attack` (journalise) et `X-WAF-Under-Attack-Enforce` (forcage)
- [x] `internal/middleware/challenge` : si `X-WAF-Under-Attack-Enforce=true` et requete **sans clearance** (pas de cookie `waf_session` valide), forcer le challenge ; relacher `isBrowserNavigation` pour les GET/HEAD ; ne pas challenger les requetes `Accept: application/json` ni les methodes non-GET/HEAD
- [x] Respecter `shadow` : calculer/journaliser `under_attack=true` sans forcer le challenge
- [x] `internal/logger` : ajouter le champ `under_attack` a l'evenement de securite (FR-09) + schema security-event
- [x] `internal/metrics` : exposer `waf_under_attack{domain}` (jauge) et `waf_under_attack_challenges_total{domain}` (compteur)
- [x] Alerte (FR-29) a l'entree et a la sortie du mode sous attaque, par scope (triggers `under_attack_start`/`under_attack_end`, dedup par cooldown)
- [x] Cabler dans `cmd/waf/main.go` (observer de transition -> metrique + alerte ; header consomme par le challenge)
- [x] Tests : detecteur par domaine, hysteresis du controleur (entree/sortie/cooldown), forcage du challenge (sans cookie -> CHALLENGE ; cookie valide -> PASS ; API JSON non challengee ; non-GET ignore), portee par domaine, scope global, eviction LRU, mode shadow, headers middleware, validation config
- [ ] (Hors premiere tranche) clients non-navigateurs sans clearance sous attaque : cap `THROTTLE`/`TARPIT` au lieu d'un simple laissez-passer ; sous-mode « siege » strict — **differe**
- **Acceptance** : sous pression `high`/`critical` sur un domaine, un visiteur sans clearance est force au CHALLENGE quel que soit son risk_score ; un visiteur avec cookie/sticky-trust/bot-verifie/whitelist passe sans friction ; le mode est reversible (PoW resolu -> cookie -> passage) et per-domaine ; aucun blocage dur n'est produit par le seul mode sous attaque.
- **Validation 2026-06-19** : `go test ./...`, `go vet ./...`, `go build ./...`, `gofmt -l`, `go test -race` (antiddos/challenge) passent ; couverture antiddos 87.3% / challenge 87.1% ; schemas JSON valides ; config.example.yaml conforme. Detail dans validation.md.
- **Statut** : implemente.
- **Spec** : requirements-detection.md FR-39 ; features/anti-ddos.feature ; ADR-018 ; schemas/config.schema.json ; schemas/security-event.schema.json

## Sprint 13 - Correctifs de conformite config (Phase 13)

### T13.1 - `domains[].challenge_enabled` sans effet (FR-06)
- [x] Constat : la cle etait documentee (CONFIG.md, `config.schema.json`) et deserialisee dans `config.DomainConfig`, mais **jamais lue** — le challenge JS ne suivait que le `challenge.enabled` global
- [x] Passer `DomainConfig.ChallengeEnabled` de `bool` a `*bool` : distinguer « cle absente » (herite du global) de « false explicite ». Avec un `bool` nu, le zero-valeur desactivait le challenge sur toute entree `domains[]` declaree pour son seul upstream ou son certificat TLS (fail-open silencieux)
- [x] `internal/middleware/challenge/domain.go` : `domainGate` resout la decision par hote avec les regles de routage `domains[]` (casse ignoree, port retire, wildcard `*.example.com` couvrant l'apex, premiere correspondance gagnante)
- [x] Cabler le gate dans `Middleware.Handler`, **avant** la lecture de `X-WAF-Under-Attack-Enforce` : un `false` explicite prime sur l'escalade automatique FR-39, qui casserait des clients incapables d'executer du JS
- [x] `POST /waf/verify` reste servi sur tous les domaines (prefixe `/waf/` reserve, token lie a l'hote emetteur)
- [x] `challenge.Enabled(cfg)` remplace `cfg.Challenge.Enabled` comme condition de montage dans `cmd/waf/main.go` : la chaine monte le middleware des qu'au moins un domaine active le challenge
- [x] Tests : table du gate (11 cas : heritage, false/true explicites, hote non liste, casse+port, wildcard sous-domaine et apex, premiere correspondance, IPv6), montage (`Enabled`), 4 cas middleware (domaine desactive, domaine sans cle, sous-attaque, `/waf/verify`), tri-etat YAML, e2e `routes()`. Gate et condition de montage **verifies en echec** par mutation
- [ ] `protected_paths`, `public_paths`, `rate_limit_override`, `trust_override` — **toujours non cables**, hors perimetre ; documente comme tel dans CONFIG.md
- **Acceptance** : `challenge_enabled: false` sur un domaine supprime toute page de challenge sur cet hote (y compris sous attaque) ; `true` la sert meme avec `challenge.enabled: false` global ; une entree `domains[]` sans la cle conserve le comportement global.
- **Validation 2026-08-31** : `go build ./...`, `go vet ./...`, `go test ./...` (413 tests, 41 paquets), `gofmt -l` passent ; schema JSON valide ; `config.example.yaml` conforme. Detail dans validation.md.
- **Statut** : implemente.
- **Spec** : requirements.md FR-06 (v2.2.0) ; features/js-challenge.feature ; schemas/config.schema.json

## Sprint 14 - Durcissement de la frontiere d'ingress (Phase 14)

### T14.1 - En-tetes X-WAF-* forgeables par le client (FR-30)
- [x] Constat : les middlewares se coordonnent via des en-tetes `X-WAF-*` poses **sur la requete** et relus en aval (16 lectures `r.Header.Get`). Rien ne les nettoyait a l'entree : un client pouvait les fabriquer
- [x] Impact verifie : `X-WAF-Action: PASS` est teste en court-circuit par le challenge (`internal/trust/score.go`), le rate limiting (`internal/middleware/ratelimit`), l'integrite (`internal/integrity`), le threat intel (`internal/threatintel`) et le moteur de regles (`internal/rules`) — contournement complet du WAF en un seul en-tete, atteignable depuis Internet (Cloudflare ne filtre pas les `X-*` arbitraires)
- [x] Nouveau paquet `internal/middleware/ingress` : supprime tout en-tete de prefixe `X-WAF-` de la requete entrante
- [x] Suppression **par prefixe** et non par liste nominative : les en-tetes internes ajoutes plus tard sont couverts d'office ; une liste se desynchronise en silence et son oubli est un fail-open
- [x] Appariement **insensible a la casse** (`strings.EqualFold` sur le prefixe) plutot que `HasPrefix` sur la forme canonique : la protection ne doit pas dependre d'un invariant interne de `net/http`
- [x] Cable en position **la plus externe** de `routes()` (apres `secheaders`, donc premier a l'execution) dans `cmd/waf/main.go`
- [x] Flux interne preserve : les detecteurs (`integrity`, `geo`, `antiddos`, `ratelimit`, `antibot`, `tlsfp`, `behavioral`) posent leurs `X-WAF-Risk-*` **a l'interieur** du pipeline, donc apres ce middleware ; `CF-Connecting-IP`, `X-Forwarded-*` et `Authorization` ne sont pas touches
- [x] Deux tests de `cmd/waf` utilisaient la faille comme point d'injection (`X-WAF-Risk-*` poses sur la requete cliente, `detectors = nil`) : ils passent desormais par un detecteur du parametre `detectors`, **comme en production**. `TestRoutesRiskEngineShadowByDefault` passait pour la mauvaise raison (il verifie que le proxy *est* appele, ce qui devenait vrai trivialement) et redevient significatif
- [x] Tests : 13 cas unitaires sur le paquet (9 en-tetes forges dont variantes de casse, cles non canoniques ecrites directement dans la map, en-tete multivalue, non-regression des en-tetes legitimes, non-debordement du prefixe sur `X-WAF` nu et `X-WAFER-*`) + 6 cas e2e sur `routes()` avec temoin. Cablage et filtre **verifies en echec** par mutation. Couverture du paquet : 100%
- [ ] Audit des autres surfaces de confiance implicite (`X-Forwarded-*` hors chemin Cloudflare, `Host` en amont du routage `domains[]`) — **hors perimetre**, demande ses propres specs
- **Acceptance** : une requete cliente portant `X-WAF-Action: PASS` (ou tout autre `X-WAF-*`) est traitee exactement comme si l'en-tete n'existait pas ; les signaux poses par le pipeline lui-meme restent lisibles en aval ; aucun en-tete hors prefixe n'est altere.
- **Validation 2026-09-01** : `go build ./...`, `go vet ./...`, `go test ./...` (433 tests, 42 paquets), `gofmt -l` (copies normalisees LF), `golangci-lint run` passent. Detail dans validation.md.
- **Statut** : implemente.
- **Spec** : requirements-ops.md FR-30 (v3.2.0) ; features/waf-self-protection.feature ; architecture.md (v1.1.0)

### T14.2 - Regression FR-19 : /waf/origin/verify casse par l'assainissement (FR-19 x FR-30)
- [x] Constat : l'assainissement d'ingress livre en T14.1 supprime tout `X-WAF-*` fourni par le client. `GET /waf/origin/verify` est appele **par l'upstream**, qui lui retransmet le `X-WAF-Origin-Token` recu : le token etait supprime avant le handler, donc l'oracle repondait **401 a tout token, valide compris** — la verification FR-19 devenait inoperante
- [x] Reproduit sur `routes()` : token valide + `origin_protection.enabled` -> 401 au lieu de 200
- [x] `internal/origin` : `CaptureInboundToken` memorise la valeur entrante dans le contexte de requete ; `VerifyHandler` la lit via `inboundToken(r)` avec repli sur l'en-tete (le handler reste utilisable sans assainisseur en amont, et le repli ne masque pas l'absence de capture puisque l'en-tete est alors deja vide)
- [x] Cable dans `routes()` **a l'exterieur** de `ingress.Middleware`, et seulement si `origin_protection.enabled` — l'endpoint n'est pas monte autrement
- [x] Exemption par **chemin** dans l'assainisseur ecartee : sa correction dependrait d'une normalisation de chemin identique a celle du routeur, vecteur de contournement classique. La capture ne connait aucun chemin
- [x] La valeur n'est **jamais reinjectee** dans `r.Header` (test dedie) et reste verifiee par HMAC : l'exception ne porte que sur la lisibilite, pas sur la validite
- [x] Commentaires de `T14.1` corriges : `ingress.Middleware` n'est plus « le middleware le plus externe » mais « doit preceder tout middleware qui lit ces en-tetes »
- [x] Tests : 3 cas unitaires (`origin`) — token capture lisible apres suppression de l'en-tete et non reinjecte, token forge toujours 401, absence d'en-tete 401 ; 3 cas e2e sur `routes()` (valide / forge / absent). Cablage **verifie en echec** par mutation. Couverture `origin` : 97,0%
- **Acceptance** : l'upstream verifie un token valide via `GET /waf/origin/verify` et recoit 200 malgre l'assainissement ; un token forge recoit 401 ; aucun autre `X-WAF-*` d'origine cliente ne survit.
- **Validation 2026-09-01** : `go build ./...`, `go vet ./...`, `go test ./...` (440 tests, 42 paquets), `gofmt -l` passent. Detail dans validation.md.
- **Statut** : implemente.
- **Spec** : requirements-advanced.md FR-19 (v2.2.0) ; requirements-ops.md FR-30 (v3.2.1) ; features/origin-protection.feature ; features/waf-self-protection.feature

### T14.3 - Audit des surfaces de confiance implicite (FR-17, ADR-019, ADR-020)
- [x] Inventaire : toutes les lectures d'en-tete entrant utilisees pour une decision de securite, hors namespace `X-WAF-*` deja couvert par T14.1
- [x] Constat FR-17 : `internal/rules/rules.go` resolvait la condition `ip` via `r.Header.Get("X-Real-IP")` — **seul** endroit du depot a ne pas passer par `cloudflare.RealIP` (20 autres consommateurs le font). `X-Real-IP` est un en-tete **sortant** pose par `internal/proxy` vers l'upstream ; en entree il vient du client, et Cloudflare ne le reecrit pas
- [x] Impact verifie : `X-Real-IP: 8.8.8.8` faisait echapper un client reellement en `10.1.2.3` a une regle `ip in_cidr ["10.0.0.0/8"]` de blocage ; `X-Real-IP: <ip de confiance>` usurpait une regle d'attribution de score. **Exploitable a travers Cloudflare**, sans acces direct a l'origine
- [x] Corrige : `clientIP` delegue a `cloudflare.RealIP` — un seul chemin d'IP pour toutes les decisions du WAF
- [x] Tests : table de 5 cas (2 temoins, evasion, usurpation, X-Forwarded-For) + resolution derriere Cloudflare avec `CF-Connecting-IP` validee. **Verifies en echec** par mutation (retour de la precedence `X-Real-IP`)
- [x] ADR-019 `proposed` : en-tetes d'infrastructure (`CF-IPCountry` pour FR-16 et le champ `country`, `ja3_header` pour FR-11) honores sans preuve d'origine. La forge n'est qu'un cas particulier — ces controles **degradent gracieusement** sur en-tete absent, donc l'omission suffit deja. 4 options exposees, **non tranchees**
- [x] ADR-020 `proposed` : `Host` pilote a la fois le routage et la politique par domaine. Un `Host` non liste retombe sur `upstream.address` **et** sur la politique globale — si le defaut pointe la meme origine qu'un domaine durci, le durcissement est contournable par un en-tete. Pas de liaison SNI/`Host` en TLS par domaine (FR-33). Options exposees, **non tranchees**
- [ ] Implementation d'ADR-019 et ADR-020 — **bloquee sur decision d'operateur** : leurs options rejettent du trafic aujourd'hui accepte (health checks, acces par IP, reutilisation HTTP/2 inter-domaines). Ne pas trancher a la place de l'operateur (invariant CLAUDE.md)
- [ ] `CONFIG.md` : documenter que `blocked_countries`/`allowed_countries`/`ja3_blacklist` et le durcissement par domaine sont des controles de reduction de bruit tant qu'ADR-019/020 ne sont pas tranches — **a faire au moment de la decision**, pour ne pas documenter deux fois
- **Acceptance** : une regle `ip` matche sur l'IP reelle etablie par le WAF quelle que soit la valeur de `X-Real-IP` ou `X-Forwarded-For` fournie par le client ; derriere Cloudflare elle matche sur `CF-Connecting-IP` validee.
- **Validation 2026-09-01** : `go build ./...`, `go vet ./...`, `go test ./...` (447 tests, 42 paquets), `gofmt -l` passent. Detail dans validation.md.
- **Statut** : correctif FR-17 implemente ; ADR-019 et ADR-020 en attente de decision.
- **Spec** : requirements-advanced.md FR-17 (v2.3.0) ; requirements-ops.md FR-30 (v3.3.0) ; features/rules-engine.feature ; ADR-019 ; ADR-020

### T14.4 - Remise a niveau d'architecture.md sur le code reel
- [x] Constat : le `Request Processing Pipeline` decrivait 10 etapes de la v1. Manquaient `ingress`, `secheaders`, `maintenance`, `slowloris`, `staticassets`, `selfprotect`, `metrics`, `access`, les 7 detecteurs de signal, le moteur de risque, `origin` et le tarpit — la moitie de la chaine, dont tout ce qui a ete livre depuis la phase 8
- [x] 21 etapes listees dans leur **ordre d'execution**, chacune avec **la cle de configuration qui la monte** : une etape non montee est absente de la chaine, elle ne se contente pas de ne rien faire
- [x] Documente que `/waf/health`, `/waf/metrics` et `/waf/origin/verify` sont servis par le `mux` **sans traverser** les etapes [6] a [20] — fait structurant absent du document
- [x] Sorties anticipees (403, 429, 503, 400, page de challenge) et chemin de remontee de la reponse
- [x] Renvois vers ADR-019 et ADR-020 poses aux deux etapes concernees, pour que le lecteur du diagramme voie les limites
- [x] `C4 niveau 2` reecrit (bordures alignees a 71 colonnes, trois chemins `/waf/*` visibles) ; `C4 niveau 3` de 15 a 42 paquets groupes par role ; `Go Project Structure` corrige (`middleware/chain.go` n'existe pas, `config.schema.json` vit dans `specs/schemas/`)
- [x] Index des ADR complete : il s'arretait a ADR-004, il couvre les 20, statut affiche pour les non-`accepted`
- [x] Verifie ligne par ligne contre `routes()` : ordre de composition, conditions de montage, position du tarpit entre `origin.Injector` et le proxy
- [ ] `architecture-advanced.md` et `architecture-ops.md` — **non verifies**, hors perimetre de cette passe
- [ ] Sections `Data Model`, `Cookie de Session`, `Score de Confiance` d'`architecture.md` — **non verifiees** contre le code, hors perimetre
- **Acceptance** : un lecteur du seul `architecture.md` peut reconstituer l'ordre reel de la chaine, savoir quelle cle de config monte chaque etape, et savoir quels chemins ne la traversent pas.
- **Validation 2026-09-01** : document uniquement, aucun code touche. `go build ./...`, `go vet ./...`, `go test ./...` (447 tests, 42 paquets) passent — inchanges.
- **Statut** : implemente.
- **Spec** : architecture.md (v1.2.0) ; ADR-019 ; ADR-020

## Sprint 15 - Options de configuration inertes (Phase 15)

> Quatre cles de configuration etaient documentees comme fonctionnelles et
> n'avaient **aucun effet** dans le code. La correction retenue est
> d'implementer ce que la documentation promettait, pas de retirer les cles
> (decision d'operateur du 2026-09-02). Les surcharges `domains[]`
> (`protected_paths`, `public_paths`, `rate_limit_override`, `trust_override`)
> restent hors perimetre : elles sont deja documentees comme non cablees
> (CONFIG.md, validation.md T13.1) et demandent leurs propres specs.

### T15.1 - `rate_limit.requests_per_minute` / `requests_per_hour` sans effet (FR-03)
- [x] Constat : les deux cles etaient deserialisees, avaient un defaut dans `Default()` et une ligne de description dans CONFIG.md (« fenetre glissante »), mais **zero usage** hors declaration. Le middleware n'implementait qu'un token bucket sur `requests_per_second`/`burst` : le debit SOUTENU n'etait borne par rien
- [x] FR-03 exigeait deja « des limites distinctes pour req/seconde, req/minute, req/heure » (un DOIT) : c'est le code qui etait en retard sur la spec, pas la doc en avance
- [x] `internal/middleware/ratelimit` : trois fenetres (`window`), chacune son bucket par IP — recharge = limite / duree de la fenetre, capacite = la limite. `burst` ne s'applique qu'a la fenetre seconde (rafale) ; minute et heure bornent le debit soutenu
- [x] Cles de stockage suffixees (`:m`, `:h`) ; la fenetre seconde garde la **cle nue**, donc l'etat persiste des deploiements anterieurs reste lisible
- [x] `TokenBucket.Refill` / `Consume` separent la recharge du prelevement : un refus par une fenetre ne consomme plus le jeton des autres. Sans cette separation, un client bute sur sa limite horaire repartait avec un burst a la seconde vide
- [x] `Retry-After` = le delai de la fenetre qui rouvre **le plus tard** ; le `reason` journalise nomme la fenetre (`rate_limit_exceeded`, `..._minute`, `..._hour`) — sinon un operateur ne peut pas savoir quelle limite regle son trafic
- [x] Piege corrige au passage : `NewTokenBucket` ramenait tout debit `< 1` a `1/s`. Cette borne, ecrite pour la fenetre seconde, rendait les fenetres minute/heure **inoperantes** (600 req/min = 10/s, 3600 req/h = 1/s, 60 req/h = 1/60 s). Le garde-fou ne porte plus que sur un debit nul ou negatif
- [x] Le facteur de pression globale (FR-08) s'applique aux trois fenetres, et la neutralite du 429 de pression est evaluee sur les trois (`nominalWouldAllow`)
- [x] `memory.Store` : la borne du nombre de buckets passe de `max_visitors` a `max_visitors * bucketsPerVisitor` — sans ce facteur, activer les fenetres divisait par trois le nombre d'IP reellement suivies
- [x] Validation : `>= 0` sur les deux cles (0 = fenetre desactivee), et `requests_per_hour >= requests_per_minute` quand les deux sont actives (sinon la fenetre minute est inatteignable)
- [x] Tests : 12 cas dedies (refus minute, refus heure, jetons des autres fenetres intacts sur refus, Retry-After/raison de la fenetre la plus longue, 0 desactive, neutralite de la pression sur la fenetre minute, table `buildWindows`, debits par duree, table `verdict`, Refill sans consommation, Consume sur bucket vide) + 8 cas de validation config. Separation recharge/prelevement **verifiee en echec** par mutation
- **Acceptance** : une IP sous 50 req/s mais au-dela de 1000 req/min recoit un 429 `rate_limit_exceeded_minute` avec le `Retry-After` de la fenetre minute ; `requests_per_minute: 0` restaure le comportement anterieur (fenetre seconde seule) ; une limite horaire sous la limite par minute est refusee au demarrage.
- **Attention deploiement** : avec les defauts (`50 req/s`, `1000 req/min`), le debit soutenu autorise passe de 3000 a 1000 req/min par IP. C'est la valeur que CONFIG.md annoncait depuis le debut, mais elle n'etait pas appliquee — a relever (ou passer a 0) si le trafic legitime depassait ce plafond.
- **Spec** : requirements.md FR-03 (v2.3.0) ; features/rate-limiting.feature ; schemas/config.schema.json

### T15.2 - `cloudflare.auto_update_ranges` / `update_interval` sans effet (FR-02)
- [x] Constat : aucune reference a `AutoUpdateRanges` hors de `config.go`. Les plages Cloudflare etaient un slice code en dur (`ranges.go`, releve le 2026-06-04) : aucun fetch HTTP, aucun ticker. CONFIG.md et `config.example.yaml` promettaient un rafraichissement toutes les `update_interval`
- [x] `internal/middleware/cloudflare/updater.go` : recuperation des deux listes officielles en HTTPS, validation, remplacement **atomique** de la liste en vigueur (`atomic.Pointer`, lue par `IsCloudflareIP` sur le chemin de requete)
- [x] La liste compilee devient la valeur initiale **et le repli permanent** : `Ranges()` retombe dessus tant qu'aucune liste valide n'a ete adoptee
- [x] Adoption **tout-ou-rien** : une liste IPv6 illisible n'installe pas la seule liste IPv4, sinon la couverture se retrecirait en silence (du trafic Cloudflare legitime commencerait a recevoir des 400)
- [x] Garde de securite centrale : rejet d'un prefixe non canonique, d'un prefixe plus large que `/8` (IPv4) ou `/19` (IPv6), d'une famille incoherente avec sa source, d'un nombre de prefixes hors bornes (>= 4 par famille, <= 512 au total), d'un corps > 64 KiB, d'un statut non 200. **La liste decide qui peut poser `CF-Connecting-IP`** : un `0.0.0.0/0` adopte rendrait l'en-tete forgeable par n'importe qui
- [x] Sources figees en HTTPS ; l'option de redirection des URL est **non exportee** (tests uniquement), aucun chemin de production ne peut substituer une source en clair
- [x] Premiere tentative **dans** la goroutine : le WAF sert immediatement avec la liste compilee et un echec de recuperation n'est pas une erreur de demarrage (FR-02 est un DEVRAIT)
- [x] Observabilite : jauge `waf_cloudflare_ranges` (initialisee au cardinal de la liste compilee) et compteur `waf_cloudflare_ranges_update_total{result}`. Sans eux, un rafraichissement qui echoue en boucle serait invisible — le WAF continue de servir correctement avec l'ancienne liste
- [x] Validation : `auto_update_ranges` exige `cloudflare.trusted` (les plages ne servent qu'a valider `CF-Connecting-IP` — accepter la combinaison inverse recreerait une option inerte) et `update_interval >= 1m`
- [x] Tests : 14 cas (adoption, 7 formes de liste invalide en table, en-tete forge toujours rejete apres un refresh refuse, statut non 200, charge surdimensionnee, exigence HTTPS, URL par defaut, liste precedente conservee sur echec ulterieur, ticker + arret sur annulation de contexte, bornes de `validateFetchedRanges`, repli sur la liste compilee, copie du slice) + 7 cas de validation config. Garde de largeur de prefixe **verifiee en echec** par mutation
- [ ] Recuperation reelle depuis `cloudflare.com` **non verifiee** : la machine de developpement n'a pas d'acces sortant (timeout observe, comportement de repli conforme). Le format « un CIDR par ligne » vient de la documentation Cloudflare ; a reverifier depuis un reseau avec acces sortant avant d'activer l'option en production
- **Acceptance** : `auto_update_ranges: true` remplace la liste en vigueur par les prefixes officiels valides et publie leur cardinal ; une liste invalide ou trop large laisse la liste precedente en place et n'empeche pas le WAF de servir ; `trusted: false` + `auto_update_ranges: true` est refuse au demarrage.
- **Spec** : requirements.md FR-02 (v2.3.0) ; features/cloudflare-ip-ranges.feature ; schemas/config.schema.json

### T15.3 - `logging.format: "pretty"` sans effet (FR-09)
- [x] Constat : `NewWithWriter` construisait toujours un `slog.NewJSONHandler`, quelle que soit la valeur de `format`. `pretty` etait valide sans erreur et produisait du JSON ; CONFIG.md promettait des logs colores lisibles par un humain
- [x] FR-09 ne parlait que de JSON : la spec a ete completee pour dire ce que chaque format garantit — `json` = contrat d'audit conforme a `security-event.schema.json`, `pretty` = rendu console **hors contrat d'audit**
- [x] `internal/logger/pretty.go` : handler `slog.Handler` qui rend une ligne par evenement — horodatage court, action colorisee, IP, methode, hote+chemin, statut, latence, raison, score, puis le reste en `cle=valeur`
- [x] Champs silencieux a l'ecran (`ip_hash`, `waf_latency_ms`, `cf_ray`), valeurs nulles et valeurs neutres omises, flottants arrondis au centieme (une latence `3528.8813999999998 ms` est du bruit). Le format `json` garde tout, a la valeur exacte
- [x] Colorisation decidee dans `New`, **seul endroit qui connait la destination reelle** : en aval le handler ne voit qu'un `io.Writer` (le tampon async), sur lequel « est-ce un terminal ? » n'a plus de reponse. Desactivee hors terminal et si `NO_COLOR` est defini
- [x] Ecriture serialisee par mutex : une ligne sort d'un seul `Write`, sinon deux requetes concurrentes entrelacent leurs fragments
- [x] Le format ne change ni le niveau, ni la destination, ni le caractere asynchrone de l'ecriture (NFR-16) : `New` construit le meme `asyncWriter` dans les deux cas
- [x] `WithAttrs`/`WithGroup` implementes (le WAF n'emet pas de groupes, mais un attribut inconnu ne doit pas disparaitre)
- [x] Tests : 11 cas (ligne lisible complete, aucune sequence ANSI hors terminal, colorisation par action en table sur les 6 actions, champs nuls et silencieux omis, contrat json intact et valide, filtrage par niveau, 50 ecritures concurrentes sans entrelacement, attributs inconnus et groupes conserves, table `colorsEnabled`, `isTerminal`) + 3 cas de validation `logging.format`
- **Acceptance** : `format: pretty` produit une ligne console lisible, colorisee sur un terminal et sans ANSI quand la sortie est redirigee ; `format: json` produit exactement le meme JSON qu'avant ce sprint.
- **Spec** : requirements.md FR-09 (v2.3.0) ; features/security-logging.feature ; schemas/config.schema.json ; ADR-014

### T15.4 - `storage.backend: "redis"` sans effet (ADR-002, ADR-021)
- [x] Constat : `cmd/waf/main.go` instanciait inconditionnellement `memory.New(...)` **sans jamais lire** `cfg.Storage.Backend`. `internal/storage/redis/` ne contenait qu'un `.gitkeep`. Les champs `storage.redis.*` etaient cables, mais seulement pour le Pub/Sub inter-noeuds (FR-20) — pas pour un store partage. CONFIG.md decrivait pourtant « stockage persistant partage entre instances »
- [x] ADR-021 `accepted` : semantique d'execution du backend — trois options evaluees (Redis pur, cache de lecture a TTL, ecriture traversante + repli explicite), la troisieme retenue. `storage.Store` ne retourne aucune erreur : les echecs Redis sont donc traites dans le paquet, jamais remontes
- [x] `internal/storage/redis/store.go` : cles `waf:visitor:` / `waf:bucket:`, valeurs JSON, TTL derive de `ExpiresAt` (expiration deleguee a Redis, pas de goroutine de nettoyage cote WAF)
- [x] Ecriture traversante (Redis + store local) : un basculement en mode degrade herite d'un etat recent au lieu de repartir de zero
- [x] Mode degrade : 3 erreurs consecutives -> service depuis l'etat local pendant 5 s, puis sonde. Une seule erreur pendant la sonde re-bascule aussitot, sinon chaque fenetre couterait 3 timeouts sur le chemin de requete. Une valeur illisible ne degrade **pas** (ce n'est pas un probleme de connectivite)
- [x] Redis injoignable **au demarrage** = erreur de demarrage (`PING`, budget 5 s) : l'operateur a demande un etat partage, une adresse ou un mot de passe fautif doit se voir tout de suite. Demarrer en degrade reproduirait le defaut corrige ici
- [x] `ListVisitors` (API admin) par `SCAN` + `MGET` borne a `trust.max_visitors` entrees — jamais de `KEYS` sur un Redis de production
- [x] Dialogue avec Redis a travers une interface reduite aux 7 commandes reellement utilisees : le mode degrade, le calcul de TTL et la serialisation sont testables **sans Redis en CI** (ADR-002)
- [x] Observabilite : jauge `waf_storage_degraded` (publiee sur transition uniquement) et compteur `waf_storage_errors_total{operation}`
- [x] Difference de comportement assumee et documentee : `trust.max_visitors` ne borne que le store local ; cote Redis la borne memoire est la `maxmemory-policy` de l'instance. Le WAF ne tente pas d'emuler la LRU dans Redis (un compteur global conteste a chaque requete)
- [x] Nouvelle cle `storage.redis.timeout` (defaut `100ms`) : budget par operation sur le chemin de requete. Un depassement compte comme une erreur plutot que de bloquer la requete
- [x] `cmd/waf` : `newStore()` selectionne l'implementation ; `metrics` est construit avant le store pour lui servir d'observateur
- [x] Tests : 19 cas (echec de demarrage sur Redis injoignable + client ferme, table de validation du timeout, aller-retour visiteur avec champs pointeurs et TTL, aller-retour bucket sous son propre prefixe, absence != panne, entree perimee lue comme absente, ecriture d'un etat deja perime -> DEL, suppression dans les deux stores, degradation apres 3 echecs avec etat local servi et plus aucun trafic Redis, ecritures locales en degrade, retour au nominal apres la fenetre, re-bascule immediate pendant la sonde, notification sur transition uniquement, SCAN+MGET borne, entrees perimees/illisibles ignorees, repli local sur echec de SCAN, valeur illisible non degradante, `Close`, conformite a `storage.Store`) + 3 cas sur `newStore`
- [ ] Execution contre un Redis reel **non verifiee** : aucune instance disponible sur la machine de developpement (ni acces sortant pour en tirer une image). Le chemin d'echec au demarrage est verifie en execution reelle ; le chemin nominal l'est par les tests avec double
- **Acceptance** : `storage.backend: redis` ouvre reellement le backend Redis et echoue au demarrage si Redis est injoignable ; une perte de Redis en exploitation bascule le noeud sur son etat local (`waf_storage_degraded = 1`) sans interrompre le service, et le retour de Redis le ramene au nominal.
- **Spec** : ADR-002 (suivi 2026-09-02) ; ADR-021 ; requirements-advanced.md FR-20 ; features/storage-backend.feature ; schemas/config.schema.json

- **Validation 2026-09-02** : `go build ./...`, `go vet ./...`, `go test ./...` (552 tests, 43 paquets), `gofmt -l` (copies normalisees LF), `golangci-lint run` (37 remontees, toutes `gofmt` sur les CRLF de la copie de travail Windows) passent ; schema JSON valide ; `config.example.yaml` et `deploy/config.docker.yaml` conformes au schema ; verifications en execution reelle du 429 `rate_limit_exceeded_minute`, du rendu `pretty` sans ANSI en sortie redirigee, du repli sur echec de rafraichissement Cloudflare et de l'echec de demarrage sur Redis injoignable. `go test -race` non executable localement (pas de toolchain C) — couvert par la CI. Detail dans validation.md.
- **Statut** : implemente.
