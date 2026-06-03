---
status: approved
version: 2.0.0
last-reviewed: 2026-06-03
extends: architecture.md (v1.0.0)
---

# Architecture Advanced — WAF Anti-DDoS / Anti-Bot (v2)

> Ce document étend `architecture.md` avec les composants avancés.

## Pipeline de requête complet (v2)

```
REQUÊTE ENTRANTE
      │
      ▼
[1]  CloudflareMiddleware
      │ Extrait CF-Connecting-IP, JA3 (si disponible), CF-IPCountry
      ▼
[2]  WhitelistMiddleware
      │ IP whitelist → PASS THROUGH (skip tout)
      ▼
[3]  BlacklistMiddleware
      │ IP blacklist → 403
      ▼
[4]  GeoRulesMiddleware          ← NOUVEAU v2
      │ CF-IPCountry → règles pays (bloc, challenge, score delta, rate override)
      ▼
[5]  ThreatIntelMiddleware        ← NOUVEAU v2
      │ Lookup cache (async si miss) : AbuseIPDB, Tor, ASN → score delta
      ▼
[6]  JA3FingerprintMiddleware     ← NOUVEAU v2
      │ JA3 blacklist check → score delta -40 si match
      ▼
[7]  RateLimitMiddleware
      │ Token Bucket par IP → 429 si vide
      ▼
[8]  AntiBotMiddleware
      │ UA, headers, honeypot paths → score delta
      ▼
[9]  AntiDDoSMiddleware
      │ Circuit-breaker, mode dégradé global
      ▼
[10] RulesEngineMiddleware        ← NOUVEAU v2
      │ Évaluation des règles custom YAML (priorité 1→N)
      ▼
[11] RequestIntegrityMiddleware   ← NOUVEAU v2
      │ Path normalization, query param analysis, body size
      ▼
[12] TrustScoreMiddleware
      │ État courant : TRUSTED → [16] Proxy
      │ CHALLENGED → [13] Challenge
      │ BLOCKED → 403
      │ Applique le score comportemental asynchrone (résultat calculé sur req précédente)
      ▼
[13] ChallengeMiddleware
      │ Cookie valide → [16] Proxy
      │ Pas de cookie → sert page HTML (difficulté adaptative)
      │ POST /waf/verify → valide PoW + timing + fingerprint + JA3 cohérence
      ▼
[14] BehaviorTrackerMiddleware    ← NOUVEAU v2
      │ Enregistre l'event dans le ring buffer (non-bloquant, channel)
      │ Lance l'analyse asynchrone si fenêtre suffisante
      ▼
[15] OriginProtectionMiddleware   ← NOUVEAU v2
      │ Injecte X-WAF-Origin-Token dans les headers upstream
      ▼
[16] ReverseProxy
      │ Proxifie vers upstream
      ▼
[17] HoneypotInjectionMiddleware  ← NOUVEAU v2
      │ Injecte liens honeypot dans réponses text/html
      ▼
[18] ResponseLogger
      │ Log JSON structuré (SecurityEvent)
      ▼
RÉPONSE → CLIENT
```

## Nouveaux packages Go (v2)

```
internal/
├── tls/
│   ├── ja3.go              # Calcul hash JA3 depuis *tls.ClientHelloInfo
│   └── listener.go         # Custom net.Listener, injection JA3 dans contexte
├── threatintel/
│   ├── manager.go          # Orchestration, cache unifié, channel async
│   ├── abuseipdb.go        # Client API AbuseIPDB v2
│   ├── tor.go              # Fetcher + set lookup tor exit nodes
│   ├── asn.go              # MaxMind GeoLite2-ASN mmdb loader + lookup
│   └── feeds.go            # Loader feeds YAML locaux
├── behavioral/
│   ├── analyzer.go         # Calcul des 6 signaux + anomaly score
│   ├── ringbuffer.go       # Ring buffer d'events par visiteur
│   ├── signals.go          # Fonctions de calcul par signal
│   └── worker.go           # Goroutine worker (channel consumer)
├── rules/
│   ├── compiler.go         # Parsing YAML + compilation structs Go
│   ├── engine.go           # Évaluation, retourne []Action
│   ├── actions.go          # Exécuteurs d'actions
│   └── context.go          # RequestContext struct
├── adaptive/
│   ├── detector.go         # Calcul AII (Attack Intensity Indicator), EMA baseline
│   └── difficulty.go       # CurrentDifficulty() avec décroissance exponentielle
├── deception/
│   ├── tarpit.go           # TarpitWriter + semaphore
│   ├── injection.go        # HTML response modifier (avant </body>)
│   └── honeypot.go         # Middleware détection visites honeypot
├── geo/
│   └── rules.go            # Matching CF-IPCountry, règles configurables
├── integrity/
│   └── checker.go          # Path normalization, param analysis, body size
├── origin/
│   ├── protection.go       # Injection X-WAF-Origin-Token
│   └── verify.go           # Handler GET /waf/origin/verify
└── cluster/
    ├── publisher.go         # Redis Pub/Sub publisher
    ├── subscriber.go        # Redis Pub/Sub subscriber + handler
    └── events.go            # Types d'événements cluster
```

## Modèle VisitorProfile étendu (v2)

```go
type VisitorProfile struct {
    // v1 fields
    IPHash          string
    Domain          string
    Score           int
    FirstSeen       time.Time
    LastSeen        time.Time
    ExpiresAt       time.Time
    ReqCount        int64
    ViolationCount  int
    ChallengePassed bool
    FPHash          string

    // v2 additions
    JA3Hash         string    // TLS fingerprint hash
    JA3Consistent   bool      // false si swap détecté
    BehaviorScore   int       // 0=humain, 100=bot (calculé asynchronement)
    Classification  string    // human/likely_human/suspicious/likely_bot/bot
    ThreatIntelHit  bool      // true si source externe a flagué cette IP
    ThreatSource    string    // quelle source (abuseipdb, tor, asn, etc.)
    GeoCountry      string    // CF-IPCountry
    ASN             string    // numéro ASN
    ASNType         string    // hosting/vpn/residential/unknown
}
```

## Flux de Threat Intelligence (v2)

```
Requête IP "X.X.X.X"
        │
        ▼
[Cache ThreatIntel] ── HIT ──▶ Applique delta immédiatement
        │
      MISS
        │
        ▼
[Channel async (non-bloquant)]
        │
        ▼ (goroutine pool, max 10 workers)
┌───────┬──────────┬───────────┐
│AbuseIPDB│ Tor List │ ASN DB   │
└───┬───┴────┬─────┴────┬──────┘
    │        │          │
    └────────┴──────────┘
               │
               ▼
        [Cache mis à jour]
        [Score appliqué requête N+1]
```

## Flux Behavioral Analysis (v2)

```
Chaque requête
     │
     ▼ (non-bloquant, channel buffered 1000)
[BehaviorChannel]
     │
     ▼ (1 goroutine worker)
[RingBuffer.Push(event)]
     │ Si buffer ≥ min_window (défaut: 10 events)
     ▼
[Analyzer.Compute()]
  ├── Signal 1: time_uniformity (std_dev intervalles)
  ├── Signal 2: path_repetition (max repeat ratio)
  ├── Signal 3: page_velocity (paths uniques/min)
  ├── Signal 4: alpha_order (séquence triée)
  └── Signal 5: asset_absence (ratio HTML vs assets)
     │
     ▼
[AnomalyScore = weighted_sum(signals)]
     │
     ▼ (atomic store dans VisitorProfile)
[TrustScore.ApplyBehavioralDelta(delta)]
```

## Configuration v2 — Nouveaux blocs

```yaml
# Threat Intelligence
threat_intel:
  enabled: true
  abuseipdb:
    enabled: true
    api_key: ""   # WAF_ABUSEIPDB_API_KEY env var
    cache_ttl: "1h"
    min_confidence_score: 50
  tor:
    enabled: true
    update_interval: "1h"
  asn:
    enabled: true
    database_path: "data/GeoLite2-ASN.mmdb"
    hostile_types: ["hosting", "vpn"]
    whitelisted_asns: ["AS13335"]  # Cloudflare

# TLS Fingerprinting
tls_fingerprint:
  enabled: true
  ja3_blacklist:
    - "3b5074b1b5d032e5620f69f9159a1b97"  # Mirai

# Behavioral Analysis
behavioral:
  enabled: true
  window_size: 50
  min_window: 10
  channel_buffer: 1000
  signal_weights:
    time_uniformity: 0.30
    path_repetition: 0.25
    page_velocity: 0.25
    alpha_order: 0.10
    asset_absence: 0.10

# Adaptive PoW
adaptive:
  enabled: true
  decay_tau_seconds: 300
  elevated_threshold: 1.10
  high_threshold: 1.50
  critical_threshold: 2.00

# Deception Layer
deception:
  enabled: false  # opt-in
  tarpit:
    enabled: true
    max_connections: 500
    chunk_size_bytes: 64
    chunk_delay_ms: 2000
    max_duration_seconds: 60
  injection:
    enabled: true
    honeypot_path_prefix: "/waf-trap/"

# Geographic Rules
geo_rules:
  - countries: ["KP"]
    action: block
  - countries: ["CN", "RU"]
    score_delta: -15
    challenge_always: true

# Custom Rules Engine
rules_engine:
  enabled: true
  rules_file: "configs/rules.yaml"

# Origin Protection
origin_protection:
  enabled: true
  # secret: "min-32-chars"   # WAF_ORIGIN_SECRET env var
  header_name: "X-WAF-Origin-Token"
  tolerance_hours: 2

# Cluster
cluster:
  enabled: false  # opt-in
  distributed_rate_limit: false
  channels:
    blacklist: "waf:blacklist"
    circuit_breaker: "waf:circuit_breaker"
    threat_share: "waf:threat_share"
    degraded_mode: "waf:degraded_mode"
```

## ADRs additionnels

- [ADR-005](decisions/ADR-005-tls-ja3-fingerprinting.md) — TLS JA3 fingerprinting
- [ADR-006](decisions/ADR-006-threat-intelligence-integration.md) — Threat Intelligence
- [ADR-007](decisions/ADR-007-custom-rules-engine.md) — Rules Engine DSL
- [ADR-008](decisions/ADR-008-deception-layer.md) — Deception Layer
- [ADR-009](decisions/ADR-009-behavioral-analysis.md) — Behavioral Analysis
- [ADR-010](decisions/ADR-010-adaptive-difficulty.md) — Adaptive PoW Difficulty
