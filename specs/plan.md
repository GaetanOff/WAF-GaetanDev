---
status: approved
version: 1.1.0
last-reviewed: 2026-06-08
---

# Plan d'implémentation — WAF Anti-DDoS / Anti-Bot

## Épics

| ID | Épic | Specs |
|----|------|-------|
| E1 | Infrastructure Go + Reverse Proxy de base | requirements FR-01, FR-02 |
| E2 | Rate Limiting + Whitelist/Blacklist | requirements FR-03, FR-04 |
| E3 | Score de confiance + Anti-Bot | requirements FR-05, FR-07 |
| E4 | Challenge JavaScript | requirements FR-06 |
| E5 | Anti-DDoS avancé | requirements FR-08 |
| E6 | Journalisation + Métriques + API Admin | requirements FR-09, FR-10 |
| E7 | Tests, CI/CD, Dockerisation | requirements NFR-04, NFR-05 |
| E8 | Moteur de Risque & Décision graduée (anti-FP) | requirements-detection FR-33..FR-38 |

---

## Slices d'implémentation

### Phase 1 — Fondations (E1 + E2 partiel)

**Slice 1.1 — Bootstrap projet Go**
- `go mod init github.com/gaetandev/waf`
- Structure de dossiers conforme à `specs/architecture.md`
- `Makefile` avec targets : `build`, `test`, `lint`, `run`
- `cmd/waf/main.go` : bootstrap, signal handling (SIGTERM graceful shutdown)
- Spec references : architecture.md

**Slice 1.2 — Config loader**
- `internal/config/config.go` : struct `Config`, `Load(path string)`, `Validate()`
- Validation au démarrage avec messages d'erreur explicites
- Override via variables d'environnement (`WAF_CHALLENGE_SECRET_KEY`, `WAF_ADMIN_TOKEN`)
- Tests unitaires `config_test.go`
- Spec references : schemas/config.schema.json

**Slice 1.3 — Reverse proxy de base**
- `internal/proxy/handler.go` : `net/http/httputil.ReverseProxy` wrapper
- Routing par domaine (Host header)
- Headers : `X-Forwarded-For`, `X-Real-IP`, `X-WAF-Score`
- Tests unitaires avec `httptest.Server`
- Spec references : requirements FR-01, architecture.md

**Slice 1.4 — Middleware Cloudflare**
- `internal/middleware/cloudflare/ranges.go` : liste statique des IP ranges Cloudflare (embed)
- `internal/middleware/cloudflare/middleware.go` : extraction `CF-Connecting-IP`
- Rejet des requêtes qui forgent le header depuis une IP non-CF
- Tests unitaires
- Spec references : requirements FR-02

**Slice 1.5 — Whitelist / Blacklist**
- `internal/storage/interface.go` : interface `Store`
- `internal/storage/memory/store.go` : implémentation in-memory avec `sync.Map` + TTL
- Whitelist/Blacklist : matching IP exact + CIDR (`net.ParseCIDR`)
- Whitelist user-agents : regex matching
- Hot-reload : watcher goroutine ou signal SIGHUP
- Spec references : requirements FR-04, features/whitelist-blacklist.feature

**Slice 1.6 — Rate Limiting**
- `internal/middleware/ratelimit/bucket.go` : Token Bucket algorithm (atomic float64)
- `internal/middleware/ratelimit/middleware.go` : HTTP 429 + `Retry-After`
- Stockage des buckets dans le Store
- Tests de charge unitaires
- Spec references : requirements FR-03, features/anti-ddos.feature

---

### Phase 2 — Intelligence (E3 + E4)

**Slice 2.1 — Score de confiance**
- `internal/trust/score.go` : `ScoreManager`, `Get`, `Apply(delta)`, `State()`
- États : TRUSTED / MONITORED / CHALLENGED / BLOCKED
- TTL expiry avec goroutine de nettoyage
- `internal/middleware/` : middleware TrustScore qui lit l'état et décide l'action
- Spec references : requirements FR-05, features/trust-score.feature

**Slice 2.2 — Détection Anti-Bot**
- `internal/middleware/antibot/rules.go` : règles user-agent (headless, curl, etc.), headers manquants
- Signatures headless : HeadlessChrome, PhantomJS, Selenium, SwiftShader WebGL
- Honeypot paths : blocage immédiat + score = 0
- Spec references : requirements FR-07, features/anti-bot.feature

**Slice 2.3 — Signing & Cookie**
- `internal/signing/hmac.go` : `Sign(payload string) string`, `Verify(payload, sig string) bool`
- `internal/middleware/challenge/cookie.go` : cookie payload, `Issue`, `Validate`
- Binding IP hash + domain + TTL
- Spec references : requirements FR-06, architecture.md (Cookie structure)

**Slice 2.4 — Challenge JS — Token & PoW**
- `internal/middleware/challenge/nonce.go` : `GenerateToken(ip, domain string) string`, `ValidateToken`
- `internal/middleware/challenge/pow.go` : `ValidatePow(token, nonce string, difficultyBits int) bool`
- Tests unitaires PoW (vecteurs connus)
- Spec references : requirements FR-06, ADR-003

**Slice 2.5 — Challenge JS — Page & Verify handler**
- `web/challenge.html` : template Go (`html/template`), injection `{{.Token}}`, `{{.Difficulty}}`, `{{.RedirectURL}}`
- `internal/middleware/challenge/middleware.go` :
  - Détection absence/invalidité cookie → serve challenge page
  - `POST /waf/verify` : parse `ChallengeSubmission`, valide token/PoW/timing/fingerprint
  - Émet cookie signé, retourne `{"redirect_url": "..."}`
- Tests d'intégration avec `httptest`
- Spec references : requirements FR-06, schemas/challenge-submission.schema.json, features/js-challenge.feature

**Slice 2.6 — Fingerprinting**
- `internal/fingerprint/fingerprint.go` : validation des signaux, calcul hash SHA-256
- Détection WebGL headless (SwiftShader, llvmpipe)
- Intégration dans le verify handler
- Spec references : requirements FR-07, ADR-004

---

### Phase 3 — Anti-DDoS avancé (E5)

**Slice 3.1 — Circuit Breaker par IP**
- `internal/middleware/antiddos/breaker.go` : compteur de violations, TTL blocage
- Ouverture après N violations consécutives, fermeture après durée configurable
- Spec references : requirements FR-08, features/anti-ddos.feature

**Slice 3.2 — Mode dégradé global**
- Détecteur de taux global (sliding window sur toutes les requêtes)
- Mode dégradé : requêtes non-trusted → 503 + Retry-After
- Spec references : requirements FR-08

---

### Phase 4 — Observabilité (E6)

**Slice 4.1 — Logger structuré**
- `internal/logger/logger.go` : wrapper `log/slog` (stdlib, voir ADR-014), injection `request_id` (UUID v4)
- Middleware de logging : log structuré par requête avec tous les champs du schéma `SecurityEvent`
- Spec references : requirements FR-09, schemas/security-event.schema.json

**Slice 4.2 — Métriques Prometheus**
- `internal/metrics/metrics.go` : définitions des counters/histograms
  - `waf_requests_total{action,domain}`
  - `waf_request_duration_seconds{action}` (histogram)
  - `waf_visitors_by_state{state}`
  - `waf_active_challenges_total`
- `GET /waf/metrics` sur le port public (ou admin selon config)
- Spec references : requirements FR-09

**Slice 4.3 — API Admin**
- `internal/admin/server.go` : serveur HTTP séparé `:9090`
- `internal/admin/handlers.go` : tous les handlers de `specs/api/admin.openapi.yaml`
- Authentification Bearer token middleware
- Spec references : requirements FR-10, api/admin.openapi.yaml

---

### Phase 5 — Production readiness (E7)

**Slice 5.1 — Tests de conformance**
- Tests d'intégration pour chaque scénario Gherkin (features/*.feature)
- Utilisation de `httptest.NewServer` pour les tests end-to-end
- Spec references : global-testing.mdc, core-quality-gates.mdc

**Slice 5.2 — CI/CD**
- GitHub Actions : lint + test + build + Docker push
- `spectral lint specs/api/admin.openapi.yaml`
- `golangci-lint run`
- `go test ./... -race -coverprofile=coverage.out`

**Slice 5.3 — Docker & Docker Compose**
- `Dockerfile` multi-stage, binaire statique, image < 30 MB
- `docker-compose.yml` : waf + nginx + redis (optionnel)

**Slice 5.4 — Documentation**
- `README.md` : installation, configuration, déploiement
- Exemple nginx.conf pour l'upstream
- Guide Cloudflare : configuration DNS proxy + headers attendus

---

### Phase 6 — Moteur de Risque & Décision (E8)

> **Pré-requis SDD** : `specs/requirements-detection.md` (FR-33..FR-38, **approuvé
> v1.0.0**) et `ADR-015` (**accepté**) sont validés après revue. La phase peut
> démarrer (invariant #1 respecté : spec approuvée avant code).
>
> Le moteur **consomme** les détecteurs existants via une interface de signaux ;
> une famille de signaux non encore implémentée (FR-11..FR-18) contribue de
> manière **neutre** par défaut, ce qui rend la phase implémentable de façon
> incrémentale sans bloquer sur les détecteurs avancés.

**Slice 6.1 — Interface de signaux + type RiskAssessment**
- `internal/risk/signal.go` : enum `SignalFamily`, struct `Contribution`,
  interface `SignalProvider` (chaque détecteur s'y adapte) ; familles absentes →
  contribution neutre
- `internal/risk/assessment.go` : struct `RiskAssessment` conforme au schéma
- Tests : sérialisation conforme à `schemas/risk-assessment.schema.json`
- Spec references : requirements-detection FR-33, NFR-17, schemas/risk-assessment.schema.json

**Slice 6.2 — Fusion pondérée + confiance + profils**
- `internal/risk/fusion.go` : combinaison pondérée → `risk_score [0..100]` +
  `confidence [0..1]` (la confiance reflète quantité/qualité des signaux)
- Config : poids par famille, profils `lenient` / `balanced` / `strict`
- Déterministe : tests table-driven (mêmes signaux → même score)
- Spec references : requirements-detection FR-33, NFR-16

**Slice 6.3 — Mapping vers l'échelle de mitigation graduée**
- `internal/risk/decision.go` : mappe `(risk_score, confidence)` → tier
  `ALLOW / OBSERVE / THROTTLE / CHALLENGE / TARPIT / BLOCK`
- Bornes de score par tier configurables et profilables
- Tests : Scenario Outline de `features/risk-scoring-engine.feature`
- Spec references : requirements-detection FR-34

**Slice 6.4 — Corroboration & signaux déterministes**
- BLOCK heuristique exige `corroborating_families >= 2` ; sinon plafond CHALLENGE
- Signaux déterministes (blacklist, honeypot, JA3 blacklisté, threat-intel
  critique, circuit breaker) → BLOCK seul, exemptés de corroboration
- Garde `block_min_confidence` : pas de BLOCK à faible confiance
- Tests : scénarios corroboration + déterministes + confiance insuffisante
- Spec references : requirements-detection FR-35

**Slice 6.5 — Allowlist de bots vérifiés (reverse-DNS)**
- `internal/risk/verifybot.go` : reverse-DNS + forward-confirm (`net.LookupAddr`
  / `net.LookupHost`, stdlib), cache TTL, **asynchrone non bloquant**
- Crawler vérifié → ALLOW, jamais de BLOCK/CHALLENGE heuristique ; UA crawler non
  vérifié → contribution `reputation` augmentée (anti-spoofing)
- Tests : Googlebot vérifié vs UA spoofé (résolveur mocké)
- Spec references : requirements-detection FR-36, NFR-08

**Slice 6.6 — Crédits de preuve humaine & trust persistant**
- Contributions négatives : challenge réussi (cookie valide), fingerprint+JA3
  stables ; intégration avec `internal/trust` et le cookie de challenge
- Sticky trust à TTL configurable ; révocation sur signal déterministe
- Garde-fou : preuve d'humanité forte → pas de BLOCK heuristique
- Tests : sticky trust, non-re-challenge, révocation honeypot
- Spec references : requirements-detection FR-37

**Slice 6.7 — Middleware de décision (intégration pipeline)**
- Câblage du moteur **après** les détecteurs et **avant** le proxy, en
  remplacement du seuil simple du Trust Score
- `RiskAssessment` injectée (forme condensée) dans l'événement de sécurité
  (FR-09) ; `score_delta` et `reason` explicites
- Tests d'intégration `httptest` : décision de bout en bout
- Spec references : requirements-detection FR-33, FR-34, NFR-17

**Slice 6.8 — Mode shadow, boucle de feedback FP & métriques**
- Mode shadow (log-only) commutable à chaud (API admin / SIGHUP)
- Boucle de feedback : un challenge réussi après flag fait décroître le poids des
  familles ayant contribué à tort (apprentissage local borné) + compteur FP
- Métriques : `waf_decisions_total{tier}`,
  `waf_challenge_pass_after_flag_total`, `waf_hard_blocks_total{corroborated}`,
  `waf_verified_bot_total{bot}`
- Tests : shadow non appliqué mais loggé ; décroissance de poids ; métriques
- Spec references : requirements-detection FR-38, NFR-15

---

## Ordre d'implémentation recommandé

```
Slice 1.1 → 1.2 → 1.3 → 1.4 → 1.5 → 1.6
               ↓
Slice 2.1 → 2.3 → 2.4 → 2.5 → 2.2 → 2.6
               ↓
Slice 3.1 → 3.2
               ↓
Slice 4.1 → 4.2 → 4.3
               ↓
Slice 5.1 → 5.2 → 5.3 → 5.4
               ↓
(requirements-detection.md approuvé v1.0.0 + ADR-015 accepté)
Slice 6.1 → 6.2 → 6.3 → 6.4 → ┬─ 6.5 ─┬→ 6.7 → 6.8
                              └─ 6.6 ─┘
```

Chaque slice laisse le projet dans un état compilable, testé et spec-conformant.
Les slices 6.5 et 6.6 sont indépendantes et parallélisables après 6.4.

## Dépendances Go recommandées

```
log/slog                           # Logging structuré (bibliothèque standard, voir ADR-014)
github.com/prometheus/client_golang # Métriques Prometheus
github.com/google/uuid             # UUID v4 pour request_id
golang.org/x/crypto                # HMAC (stdlib suffit pour SHA-256)
gopkg.in/yaml.v3                   # Parsing YAML config
github.com/go-redis/redis/v9       # Client Redis (optionnel)
github.com/stretchr/testify        # Assertions tests
```

Pas de framework web (net/http stdlib suffit).
