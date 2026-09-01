---
status: approved
version: 1.2.0
last-reviewed: 2026-09-01
change: "Remise à niveau du Request Processing Pipeline, du C4 niveau 2/3 et de la structure projet sur le code réel : 21 étapes dans leur ordre d'exécution avec leur clé de montage, 42 paquets internes, chemins /waf/* qui ne traversent pas la chaîne"
---

# Architecture — WAF Anti-DDoS / Anti-Bot

## C4 Level 1 — System Context

```
┌─────────────────────────────────────────────────────────────────┐
│                          INTERNET                               │
│                                                                 │
│   [Visiteur Humain]  [Bot Malveillant]  [Attaquant DDoS]       │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTPS
                           ▼
                   ┌───────────────┐
                   │  Cloudflare   │  Protection L3/L4, CDN, TLS
                   │  (DNS Proxy)  │
                   └───────┬───────┘
                           │ HTTP (CF-Connecting-IP header)
                           ▼
                   ┌───────────────┐
                   │   WAF Go      │  ← CE SYSTÈME
                   │  :8080        │  Analyse, filtre, challenge
                   └───────┬───────┘
                           │ HTTP (requêtes légitimes seulement)
                           ▼
              ┌────────────┴────────────┐
              │                         │
      ┌───────────────┐       ┌───────────────────┐
      │     Nginx     │       │  Serveur d'Origine │
      │  (optionnel)  │──────▶│  (App/Backend)     │
      └───────────────┘       └───────────────────┘
```

## C4 Level 2 — Containers

```
┌─────────────────────────────────────────────────────────────────────┐
│                        WAF Go Application                           │
│                                                                     │
│  ┌───────────────────────┐    ┌──────────────────────────────────┐  │
│  │  Listener public      │    │      Middleware Pipeline         │  │
│  │  :443 HTTPS (SNI)     │───▶│  ingress → secheaders →          │  │
│  │  :80  redirect + ACME │    │  maintenance → slowloris → mux   │  │
│  └───────────────────────┘    │    ├── /waf/health               │  │
│                               │    ├── /waf/metrics              │  │
│  ┌───────────────────────┐    │    ├── /waf/origin/verify        │  │
│  │  Admin API :9090      │    │    └── "/" → staticassets →      │  │
│  │  (privée, token)      │    │        selfprotect → cloudflare →│  │
│  └───────────┬───────────┘    │        metrics → logger →        │  │
│              │                │        access → antiddos →       │  │
│              │                │        challenge → ratelimit →   │  │
│              │                │        antibot → détecteurs →    │  │
│              │                │        risque | trust → origin → │  │
│              │                │        tarpit → proxy → upstream │  │
│              │                └──────────────┬───────────────────┘  │
│              │                               │                      │
│              │       ┌───────────────────────▼───────────────────┐  │
│              └──────▶│               State Store                 │  │
│                      │  Visiteurs · buckets · nonces · preuves   │  │
│                      │  memory (LRU + TTL) | redis (multi-nœuds) │  │
│                      └───────────────────────────────────────────┘  │
│                                                                     │
│  ┌───────────────────────┐    ┌──────────────────────────────────┐  │
│  │  Config Engine        │    │  Alerting · Audit · Cluster      │  │
│  │  YAML + env + reload  │    │  webhooks · GDPR · sync Redis    │  │
│  └───────────────────────┘    └──────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

> L'ordre exact, les conditions de montage et les sorties anticipées sont dans la
> section *Request Processing Pipeline*.

## C4 Level 3 — Components (internal packages)

```
internal/
├── middleware/          Middlewares de la chaîne publique
│   ├── ingress/         Suppression des X-WAF-* fournis par le client (FR-30)
│   ├── cloudflare/      Plages Cloudflare, extraction de CF-Connecting-IP (FR-02)
│   ├── access/          Whitelist / blacklist IP, CIDR, user-agent (FR-04)
│   ├── antiddos/        Pression globale et par domaine, circuit breaker,
│   │                    mode « sous attaque » (FR-08, FR-39)
│   ├── challenge/       Nonce, page PoW, /waf/verify, cookie, gate par domaine (FR-06)
│   ├── ratelimit/       Token bucket par IP, throttle de pression (FR-03)
│   └── antibot/         Heuristiques UA et en-têtes, honeypots (FR-07)
│
├── Détecteurs de signal (consommés par le moteur de risque)
│   ├── integrity/       Cohérence de la requête (FR-18)
│   ├── behavioral/      Séquences de navigation (FR-12)
│   ├── threatintel/     Réputation d'IP, sources statiques + AbuseIPDB (FR-13)
│   ├── geo/             Règles géographiques via CF-IPCountry (FR-16)
│   ├── tlsfp/           JA3 : blacklist et détection de swap (FR-11)
│   ├── rules/           Moteur de règles YAML compilé (FR-17)
│   ├── fingerprint/     Signaux navigateur et hash d'empreinte (FR-06)
│   └── adaptive/        Difficulté PoW pilotée par la pression (FR-14, FR-16)
│
├── Décision
│   ├── risk/            Fusion de familles, corroboration, mitigation
│   │                    graduée, mode shadow (FR-33..FR-38)
│   └── trust/           Score de confiance, TTL, seuils (FR-05)
│
├── Sortie et transport
│   ├── proxy/           ReverseProxy, routage par Host, réécriture d'en-têtes (FR-01)
│   ├── origin/          Token HMAC vers l'upstream + oracle de vérification (FR-19)
│   ├── upstream/        Health checks, failover, load balancing (FR-25, FR-26)
│   ├── upstreamtime/    Mesure du temps passé côté upstream (FR-09)
│   ├── tlsmgr/          Certificats par domaine, sélection par SNI (FR-33)
│   └── acme/            Let's Encrypt via autocert (FR-31)
│
├── Réponse au client
│   ├── secheaders/      Injection d'en-têtes, masquage upstream (FR-21, FR-22)
│   ├── maintenance/     Page de maintenance, erreurs brandées (FR-32)
│   ├── staticassets/    Bypass des assets statiques (FR-24)
│   ├── slowloris/       Borne de connexions concurrentes par IP (FR-23)
│   ├── selfprotect/     Garde de flood sur /waf/verify (FR-30)
│   └── deception/       Tarpit et contenu honeypot (FR-15)
│
├── État
│   └── storage/
│       ├── memory/      sync.Map + éviction LRU + TTL
│       └── redis/       Adaptateur Redis, même interface (FR-20)
│
└── Transverse
    ├── config/          Struct, chargement YAML, override env, Validate()
    ├── logger/          Événement de sécurité JSON via log/slog (FR-09)
    ├── metrics/         Compteurs et histogrammes Prometheus (RED)
    ├── admin/           Serveur et handlers de l'API admin :9090 (FR-10)
    ├── audit/           Journal d'audit des actions admin (FR-27)
    ├── alert/           Webhooks Discord, Slack, génériques (FR-29)
    ├── cluster/         Synchronisation d'état inter-nœuds (FR-20)
    ├── gdpr/            Anonymisation, rétention, registre (FR-28)
    ├── signing/         HMAC-SHA256 : signature et validation
    └── jsonstrict/      Parsing JSON durci sur les entrées non fiables (FR-30)
```

## Request Processing Pipeline

> Ordre d'**exécution** réel, tel que composé par `routes()` dans
> `cmd/waf/main.go`. Beaucoup d'étapes sont montées conditionnellement : la clé de
> configuration qui les monte est indiquée. Une étape non montée est absente de la
> chaîne, elle ne se contente pas de ne rien faire.
>
> Les middlewares se coordonnent en posant des en-têtes `X-WAF-*` **sur la
> requête**, relus en aval. `X-WAF-Action: PASS` est un court-circuit honoré par
> le challenge, le rate limiting, l'intégrité, le threat intel, le moteur de
> règles, la géo et le TLSFP. Ces en-têtes sont de l'état interne : FR-30 impose
> leur suppression à l'entrée.

```
REQUÊTE ENTRANTE
      │
      ▼
── Enveloppe (tous les chemins, y compris /waf/*) ────────────────────────────────
      │
[0] origin.CaptureInboundToken            si origin_protection.enabled
      │ Mémorise le X-WAF-Origin-Token entrant dans le contexte.
      │ Seule exception à [1] : l'upstream le retransmet à
      │ /waf/origin/verify, qui le vérifie par HMAC (FR-19).
      ▼
[1] ingress.Middleware                    toujours
      │ Supprime TOUT en-tête X-WAF-* fourni par le client (FR-30).
      │ Doit précéder tout middleware qui lit ces en-têtes.
      ▼
[2] secheaders                            si security_headers.enabled
      │ Injecte les en-têtes de sécurité et masque les en-têtes
      │ révélateurs de l'upstream en réponse (FR-21/FR-22).
      ▼
[3] maintenance                           toujours (inactif si non configuré)
      │ Page de maintenance + pages d'erreur brandées (FR-32).
      ▼
[4] slowloris                             si slowloris.enabled
      │ Borne les requêtes concurrentes par IP (FR-23).
      ▼
[5] http.ServeMux
      │ /waf/health          → healthHandler
      │ /waf/metrics         → handler Prometheus
      │ /waf/origin/verify   → origin.VerifyHandler   si origin_protection.enabled
      │ /                    → chaîne de protection ci-dessous
      │
      │ Les trois chemins /waf/* ci-dessus sont servis directement :
      │ ils ne traversent PAS les étapes [6] à [20].
      ▼
── Chaîne de protection (chemin "/" uniquement) ─────────────────────────────────
      │
[6] staticassets                          si static_assets.enabled
      │ Bypass des assets statiques : pose X-WAF-Action=PASS (FR-24).
      │ La blacklist reste appliquée en [11].
      ▼
[7] selfprotect.PathGuard("/waf/verify")  si self_protection.enabled
      │ Limite le flood de POST /waf/verify par IP (FR-30).
      ▼
[8] cloudflare.Middleware                 si cloudflare.trusted
      │ Valide que la source appartient aux plages Cloudflare, puis
      │ retient CF-Connecting-IP comme IP réelle ; 400 si l'en-tête
      │ est présent hors plage Cloudflare (FR-02).
      │ Non monté : l'IP réelle est celle de la connexion.
      │ ⚠ Les autres CF-* ne sont pas validés — cf. ADR-019.
      ▼
[9] metrics.Middleware                    toujours
      │ Compteurs et histogrammes Prometheus (RED).
      ▼
[10] logger.Middleware                    toujours
      │ Événement de sécurité JSON structuré (FR-09).
      ▼
[11] access.Middleware                    toujours
      │ Whitelist IP/CIDR/UA → X-WAF-Action=PASS.
      │ Blacklist IP/CIDR    → 403 (FR-04).
      ▼
[12] antiddos.Handler                     toujours
      │ Pression globale ou par domaine, circuit breaker,
      │ mode « sous attaque » → X-WAF-Under-Attack-Enforce (FR-08/FR-39).
      ▼
[13] challenge.Handler                    si challenge.Enabled(cfg)
      │ Monté dès qu'un hôte peut être challengé — global ou
      │ domains[].challenge_enabled. Décision par hôte dans le
      │ middleware. Sert la page PoW, traite POST /waf/verify,
      │ émet le cookie signé (FR-06).
      ▼
[14] ratelimit.Handler                    si rate_limit.enabled
      │ Token bucket par IP, throttle piloté par la pression (FR-03).
      ▼
[15] antibot.Handler                      toujours
      │ Heuristiques User-Agent et en-têtes, honeypots (FR-07).
      ▼
[16] Détecteurs de signal — dans cet ordre, chacun conditionnel
      │ integrity     toujours              Cohérence de la requête (FR-18)
      │ adaptive      si adaptive.enabled   Difficulté PoW adaptative (FR-14)
      │ behavioral    si behavioral.enabled Séquences de navigation (FR-12)
      │ threatintel   si threat_intel.…     Réputation d'IP (FR-13)
      │ geo           si geo.enabled        Règles géographiques (FR-16)
      │ tlsfp         si tls_fingerprint.…  JA3 : blacklist et swap (FR-11)
      │ rules         si rules.enabled      Moteur de règles YAML (FR-17)
      │
      │ Chacun publie sa contribution dans un X-WAF-Risk-<famille>
      │ consommé en [17]. geo et tlsfp peuvent bloquer directement.
      ▼
[17] Décision
      │ si risk_engine.enabled → risk.Handler
      │     Fusion des familles, corroboration, échelle de mitigation
      │     graduée, mode shadow (FR-33..FR-38)
      │ sinon                  → trust.ScoreManager.Middleware
      │     Score de confiance seul : BLOCK ou CHALLENGE au seuil (FR-05)
      ▼
[18] origin.Injector                      si origin_protection.enabled
      │ Pose X-WAF-Origin-Token = HMAC(secret, hôte + heure) sur la
      │ requête ; le proxy le transmet à l'upstream (FR-19).
      ▼
[19] deception.Tarpit.Dispatch            si deception.enabled
      │ Intercepte les requêtes classées TARPIT en [17] et sert une
      │ réponse volontairement lente et fragmentée (FR-15).
      │ Les autres passent au proxy.
      ▼
[20] proxy.Handler
      │ Routage par Host vers domains[].upstream, repli sur
      │ upstream.address (⚠ cf. ADR-020). Pool avec health checks et
      │ load balancing si configuré (FR-25/FR-26).
      │ Pose X-Forwarded-*, X-Real-IP et X-WAF-Score vers l'upstream.
      ▼
RÉPONSE UPSTREAM → [10] journalise → [9] mesure → [2] en-têtes → CLIENT
```

**Sorties anticipées.** Toute étape peut répondre sans appeler la suivante :
`403` (blacklist, géo, règle, JA3 blacklist, score sous le seuil de blocage),
`429` (rate limit, self-protection), `503` (circuit breaker, maintenance),
`400` (`CF-Connecting-IP` forgé, `Host` invalide sur le redirecteur), ou la page
de challenge (`200 text/html`). La réponse traverse alors en remontée les étapes
déjà franchies — donc `[10]` la journalise et `[2]` l'habille.

**Serveurs séparés.** L'API admin (`:9090`), le redirecteur HTTP→HTTPS et le
serveur de challenge ACME ont leurs propres chaînes et ne traversent aucune des
étapes ci-dessus.

## JavaScript Challenge — Séquence détaillée

```
Client                        WAF                         Browser JS
  │                            │
  │  GET /page                 │
  ├───────────────────────────▶│
  │                            │ score < challenge_threshold
  │  HTTP 200 + challenge.html │
  │◀───────────────────────────┤
  │                            │  (page animée, chronomètre démarré)
  │                            │
  │  (JS s'exécute)            │
  │  - génère fingerprint      │
  │  - résout proof-of-work    │
  │  - attend min 500ms        │
  │                            │
  │  POST /waf/verify          │
  │  {token, pow, fingerprint, │
  │   elapsed_ms}              │
  ├───────────────────────────▶│
  │                            │ valide token (HMAC + TTL 30s)
  │                            │ valide proof-of-work
  │                            │ valide elapsed_ms (500ms..10s)
  │                            │ met à jour score (+25)
  │                            │ émet cookie signé
  │  HTTP 200 {redirect_url}   │
  │◀───────────────────────────┤
  │                            │
  │  (JS redirige vers URL)    │
  │                            │
  │  GET /page (+ cookie)      │
  ├───────────────────────────▶│
  │                            │ cookie valide → PASS THROUGH
  │  HTTP 200 (contenu réel)   │
  │◀───────────────────────────┤
```

## Cookie de Session — Structure

```
Format : waf_session=<base64(payload)>.<base64(hmac)>

Payload JSON :
{
  "ip_hash": "<SHA-256(ip)[:16]>",
  "fp_hash": "<SHA-256(fingerprint)[:16]>",
  "domain": "example.com",
  "issued_at": 1748880000,
  "expires_at": 1748966400,
  "score": 75
}

HMAC = HMAC-SHA256(secret_key, base64(payload))
```

## Score de Confiance — Automate

```
État         Score    Action
──────────────────────────────────────────
TRUSTED      70-100   Pass through direct
MONITORED    40-69    Pass + log
CHALLENGED   11-39    JS Challenge requis
BLOCKED      0-10     403 Forbidden
```

**Transitions de score :**

| Événement | Delta |
|-----------|-------|
| Challenge JS réussi | +25 |
| Navigation normale (req légitime) | +1 (max +10/heure) |
| Requête à un honeypot | -50 |
| Challenge JS échoué | -20 |
| Rate limit atteint | -10 |
| User-agent headless browser | -30 |
| User-agent suspect (curl, python-requests sans whitelist) | -15 |
| Header manquant (Accept-Language) | -5 |
| Proof-of-work trop rapide (< 100 ms) | -20 |

## Data Model

### VisitorState

```
VisitorState {
  ip_hash      string    // SHA-256(ip_address)[:16], non-réversible
  domain       string
  score        int       // 0..100
  last_seen    time.Time
  expires_at   time.Time // TTL = 1h par défaut
  req_count    int64
  violation_count int
  challenge_passed bool
  fp_hash      string    // hash du fingerprint navigateur (si disponible)
}
```

### SecurityEvent

```
SecurityEvent {
  timestamp    time.Time
  request_id   string    // UUID v4
  ip           string    // IP réelle (non hashée, pour logs internes)
  domain       string
  method       string
  path         string    // path seulement, pas query string
  user_agent   string
  action       string    // PASS | CHALLENGE | BLOCK | RATE_LIMIT
  reason       string    // description de la règle déclenchée
  trust_score  int
  latency_ms   float64
  upstream_status int
}
```

### RateBucket

```
RateBucket {
  ip_hash      string
  tokens       float64   // token bucket courant
  last_refill  time.Time
  rate         float64   // tokens/seconde
  capacity     float64   // capacité max
}
```

## Go Project Structure

> Pour le détail des responsabilités par paquet, voir *C4 Level 3* ci-dessus.

```
waf/
├── cmd/
│   └── waf/
│       ├── main.go              # Bootstrap, construction de la chaîne (routes())
│       └── main_test.go         # Tests e2e sur routes()
├── internal/                    # 42 paquets — cf. C4 Level 3
├── web/
│   └── challenge.html           # Template HTML/CSS/JS du challenge PoW
├── configs/
│   └── config.example.yaml      # Exemple de configuration complète
├── specs/                       # Specs SDD — source de vérité
│   ├── api/                     # Contrats OpenAPI 3.1 (API admin)
│   ├── schemas/                 # JSON Schema, dont config.schema.json
│   ├── features/                # Specs de comportement Gherkin
│   ├── decisions/               # ADR
│   ├── requirements*.md         # FR-01..FR-39, NFR
│   ├── architecture*.md         # Ce document et ses compléments
│   ├── plan.md, tasks.md        # Découpage en tranches et tâches
│   ├── validation.md            # Journal des gates et décisions de triage
│   └── changelog.md             # Keep a Changelog
├── .github/workflows/           # CI : lint, test (race + couverture), Trivy, Semgrep
├── .golangci.yml                # Configuration golangci-lint v2
├── .spectral.yaml               # Ruleset Spectral pour l'OpenAPI admin
├── .trivyignore
├── CONFIG.md                    # Référence des clés de configuration
├── SECURITY.md
├── AGENTS.md, CLAUDE.md         # Instructions agents / SDD
├── Dockerfile                   # Build multi-stage, utilisateur non root
├── docker-compose.yml
├── Makefile                     # build, test, lint, run, docker-build
├── go.mod, go.sum
└── README.md
```

## ADRs Référencés

- [ADR-001](decisions/ADR-001-go-language-choice.md) — Choix du langage : Go vs Bun/TypeScript
- [ADR-002](decisions/ADR-002-storage-backend.md) — Backend de stockage de l'état des visiteurs
- [ADR-003](decisions/ADR-003-js-challenge-strategy.md) — Stratégie du challenge JavaScript
- [ADR-004](decisions/ADR-004-fingerprinting.md) — Approche fingerprinting navigateur
- [ADR-005](decisions/ADR-005-tls-ja3-fingerprinting.md) — TLS/JA3 Fingerprinting
- [ADR-006](decisions/ADR-006-threat-intelligence-integration.md) — Intégration Threat Intelligence externe
- [ADR-007](decisions/ADR-007-custom-rules-engine.md) — Moteur de Règles Personnalisées
- [ADR-008](decisions/ADR-008-deception-layer.md) — Deception Layer (Tarpit + Honeypot Content)
- [ADR-009](decisions/ADR-009-behavioral-analysis.md) — Behavioral Sequence Analysis
- [ADR-010](decisions/ADR-010-adaptive-difficulty.md) — Adaptive PoW Difficulty
- [ADR-011](decisions/ADR-011-security-headers.md) — Stratégie Security Headers
- [ADR-012](decisions/ADR-012-upstream-health-loadbalancing.md) — Upstream Health Checks & Load Balancing
- [ADR-013](decisions/ADR-013-gdpr-compliance.md) — Conformité GDPR & Privacy by Design
- [ADR-014](decisions/ADR-014-logging-library.md) — Bibliothèque de logging : log/slog (stdlib) vs zerolog
- [ADR-015](decisions/ADR-015-risk-scoring-decision-engine.md) — Moteur de Scoring de Risque & Décision graduée
- [ADR-016](decisions/ADR-016-adaptive-global-pressure.md) — Pression globale adaptative au lieu du 503 global
- [ADR-017](decisions/ADR-017-per-domain-tls.md) — Terminaison TLS par domaine (sélection par SNI)
- [ADR-018](decisions/ADR-018-under-attack-mode.md) — Mode « sous attaque » : challenge forcé piloté par la pression
- [ADR-019](decisions/ADR-019-infrastructure-header-trust.md) — Frontière de confiance des en-têtes d'infrastructure (`CF-*`, `ja3_header`) **(`proposed`)**
- [ADR-020](decisions/ADR-020-host-header-routing-trust.md) — Confiance accordée à l'en-tête `Host` pour le routage et la politique par domaine **(`proposed`)**
