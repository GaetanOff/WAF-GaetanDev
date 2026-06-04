---
status: approved
version: 1.0.0
last-reviewed: 2026-06-03
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
┌─────────────────────────────────────────────────────────────────┐
│                        WAF Go Application                       │
│                                                                 │
│  ┌──────────────┐    ┌───────────────────────────────────────┐  │
│  │  HTTP Server │    │           Middleware Pipeline         │  │
│  │   :8080      │───▶│  CF-IP → Whitelist → Blacklist →     │  │
│  │  (public)    │    │  RateLimit → BotDetect → TrustScore  │  │
│  └──────────────┘    │  → Challenge → Proxy                 │  │
│                      └───────────────────┬───────────────────┘  │
│  ┌──────────────┐                        │                      │
│  │  Admin API   │    ┌───────────────────▼───────────────────┐  │
│  │   :9090      │    │          State Store (in-memory)      │  │
│  │  (private)   │───▶│  Visitors / Rate Buckets / Nonces    │  │
│  └──────────────┘    │  (+ Redis optionnel pour multi-nœud) │  │
│                      └───────────────────────────────────────┘  │
│  ┌──────────────┐    ┌───────────────────────────────────────┐  │
│  │  Metrics     │    │           Config Engine               │  │
│  │   /waf/      │    │  YAML loader + hot-reload + validate  │  │
│  │   metrics    │    └───────────────────────────────────────┘  │
│  └──────────────┘                                               │
└─────────────────────────────────────────────────────────────────┘
```

## C4 Level 3 — Components (internal packages)

```
internal/
├── config/          Config struct, YAML loader, env override, validator
├── proxy/           ReverseProxy wrapper (net/http/httputil), header rewrite
├── middleware/
│   ├── cloudflare/  IP range validation, CF-Connecting-IP extraction
│   ├── ratelimit/   Token Bucket per IP, sliding window, 429 response
│   ├── antibot/     User-agent analysis, header heuristics, honeypot
│   ├── antiddos/    Circuit breaker, global rate, slow-down
│   └── challenge/   Nonce generation, JS page serving, response validation
├── trust/           Score management, TTL expiry, threshold evaluation
├── fingerprint/     Browser signal parsing, fingerprint hash computation
├── storage/
│   ├── memory/      sync.Map + LRU eviction, TTL cleanup goroutine
│   └── redis/       Redis adapter (optionnel, même interface)
├── signing/         HMAC-SHA256 cookie signing/validation
├── logger/          Structured JSON logger (log/slog, stdlib), request_id injection
└── metrics/         Prometheus counters/histograms, /waf/metrics handler
```

## Request Processing Pipeline

```
REQUÊTE ENTRANTE
      │
      ▼
[1] CloudflareMiddleware
      │ Vérifie IP source ∈ ranges Cloudflare
      │ Extrait CF-Connecting-IP comme IP réelle
      │ Rejette si tentative de forge
      ▼
[2] WhitelistMiddleware
      │ IP ∈ whitelist CIDR ? → PASS THROUGH (skip tout)
      │ Bot légitime user-agent ? → PASS THROUGH
      ▼
[3] BlacklistMiddleware
      │ IP ∈ blacklist ? → 403 Forbidden
      ▼
[4] RateLimitMiddleware
      │ Token bucket pour cette IP
      │ Bucket vide ? → 429 + décrémente score (-10)
      │ Bucket OK → consomme 1 token
      ▼
[5] AntiBotMiddleware
      │ User-Agent vide/suspect → score -= 15..30
      │ Headers manquants (Accept, Accept-Encoding) → score -= 5
      │ URL honeypot → score = 0, log event
      ▼
[6] AntiDDoSMiddleware
      │ Taux global > seuil → mode dégradé
      │ IP: N violations consécutives → circuit-breaker
      ▼
[7] TrustScoreMiddleware
      │ score < block_threshold → 403
      │ score < challenge_threshold → → [8] Challenge
      │ score >= challenge_threshold → → [9] Proxy
      ▼
[8] ChallengeMiddleware
      │ Cookie valide ? → met à jour score, → [9] Proxy
      │ Pas de cookie → sert page HTML challenge
      │ POST /waf/verify → valide réponse JS
      │   → OK : émet cookie signé, redirect
      │   → KO : décrémente score, re-challenge
      ▼
[9] ReverseProxy
      │ Proxifie vers upstream (domaine-specific)
      │ Ajoute X-Forwarded-For, X-Real-IP, X-WAF-Score
      ▼
[10] ResponseLogger
      │ Log JSON : ip, domain, path, status, latency, action, score
      ▼
RÉPONSE UPSTREAM → CLIENT
```

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

```
waf/
├── cmd/
│   └── waf/
│       └── main.go              # Point d'entrée, bootstrap
├── internal/
│   ├── config/
│   │   ├── config.go            # Struct Config + Load() + Validate()
│   │   └── config_test.go
│   ├── proxy/
│   │   ├── handler.go           # ReverseProxy, domain routing
│   │   └── handler_test.go
│   ├── middleware/
│   │   ├── chain.go             # Composition de middlewares
│   │   ├── cloudflare/
│   │   │   ├── middleware.go
│   │   │   ├── ranges.go        # IP ranges Cloudflare
│   │   │   └── middleware_test.go
│   │   ├── ratelimit/
│   │   │   ├── middleware.go
│   │   │   ├── bucket.go        # Token Bucket algorithm
│   │   │   └── middleware_test.go
│   │   ├── antibot/
│   │   │   ├── middleware.go
│   │   │   ├── rules.go         # User-agent rules, header checks
│   │   │   └── middleware_test.go
│   │   ├── antiddos/
│   │   │   ├── middleware.go
│   │   │   ├── breaker.go       # Circuit breaker
│   │   │   └── middleware_test.go
│   │   └── challenge/
│   │       ├── middleware.go
│   │       ├── nonce.go         # Token generation + validation
│   │       ├── pow.go           # Proof-of-work validation (Go side)
│   │       ├── cookie.go        # Cookie signing/validation
│   │       └── middleware_test.go
│   ├── trust/
│   │   ├── score.go             # Score management, threshold evaluation
│   │   └── score_test.go
│   ├── fingerprint/
│   │   ├── fingerprint.go       # Parse + hash browser signals
│   │   └── fingerprint_test.go
│   ├── storage/
│   │   ├── interface.go         # Store interface
│   │   ├── memory/
│   │   │   ├── store.go         # In-memory store avec LRU + TTL
│   │   │   └── store_test.go
│   │   └── redis/
│   │       ├── store.go         # Redis adapter
│   │       └── store_test.go
│   ├── admin/
│   │   ├── server.go            # Admin HTTP server :9090
│   │   ├── handlers.go          # Admin API handlers
│   │   └── handlers_test.go
│   ├── signing/
│   │   ├── hmac.go              # HMAC-SHA256 sign/verify
│   │   └── hmac_test.go
│   ├── logger/
│   │   ├── logger.go            # log/slog wrapper, request_id injection
│   │   └── fields.go            # Log field constants
│   └── metrics/
│       ├── metrics.go           # Prometheus metrics definitions
│       └── handler.go           # /waf/metrics HTTP handler
├── web/
│   └── challenge.html           # Template HTML/CSS/JS du challenge
├── configs/
│   ├── config.example.yaml      # Exemple de configuration complète
│   └── config.schema.json       # JSON Schema de validation
├── specs/                       # Ce répertoire (specs SDD)
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── go.mod
├── go.sum
└── README.md
```

## ADRs Référencés

- [ADR-001](decisions/ADR-001-go-language-choice.md) — Choix Go vs Bun
- [ADR-002](decisions/ADR-002-storage-backend.md) — Stockage état visiteurs
- [ADR-003](decisions/ADR-003-js-challenge-strategy.md) — Stratégie challenge JS
- [ADR-004](decisions/ADR-004-fingerprinting.md) — Approche fingerprinting navigateur
