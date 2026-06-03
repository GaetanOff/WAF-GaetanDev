---
status: approved
version: 3.0.0
last-reviewed: 2026-06-03
extends: architecture-advanced.md (v2.0.0)
---

# Architecture Ops — WAF Anti-DDoS / Anti-Bot (v3)

> Ce document étend `architecture-advanced.md` avec les composants opérationnels manquants.

## Pipeline de requête complet (v3 — final)

```
REQUÊTE ENTRANTE (TCP)
      │
      ▼
[0]  SlowlorisGuard                  ← NOUVEAU v3
      │ Timeout headers (10s), débit minimum body, max connexions/IP
      ▼
[1]  CloudflareMiddleware
      │ Extrait CF-Connecting-IP, JA3, CF-IPCountry
      ▼
[2]  WhitelistMiddleware
      │ IP whitelist → PASS THROUGH
      ▼
[3]  BlacklistMiddleware
      │ IP blacklist → 403
      ▼
[4]  StaticAssetsBypassMiddleware    ← NOUVEAU v3
      │ Extension .css/.js/.png/etc → skip [5..13] → va directement au proxy
      ▼
[5]  GeoRulesMiddleware
      │ CF-IPCountry → règles pays
      ▼
[6]  ThreatIntelMiddleware
      │ AbuseIPDB, Tor, ASN (async cache)
      ▼
[7]  JA3FingerprintMiddleware
      │ JA3 blacklist check
      ▼
[8]  RateLimitMiddleware
      │ Token Bucket, 429 si vide
      ▼
[9]  AntiBotMiddleware
      │ UA, headers, honeypot paths
      ▼
[10] AntiDDoSMiddleware
      │ Circuit-breaker, mode dégradé
      ▼
[11] RulesEngineMiddleware
      │ Règles YAML custom
      ▼
[12] RequestIntegrityMiddleware
      │ Path traversal, injection patterns
      ▼
[13] WafSelfProtectionMiddleware     ← NOUVEAU v3
      │ Rate limit /waf/verify, nonce replay, admin brute-force
      ▼
[14] TrustScoreMiddleware
      │ TRUSTED → [17] Proxy
      │ CHALLENGED → [15] Challenge
      │ BLOCKED → 403 (page custom)
      ▼
[15] ChallengeMiddleware
      │ Cookie valide → [17] Proxy
      │ Pas de cookie → page challenge (adaptive difficulty)
      │ POST /waf/verify → valide tout
      ▼
[16] BehaviorTrackerMiddleware
      │ Ring buffer event (non-bloquant)
      ▼
[17] OriginProtectionMiddleware
      │ Injecte X-WAF-Origin-Token
      ▼
[18] UpstreamPool.Select()           ← NOUVEAU v3 (remplace ReverseProxy direct)
      │ Round-robin / ip-hash / least-conn
      │ Health check → upstream UP ?
      │ Tous DOWN → page maintenance
      ▼
[19] ReverseProxy
      │ Proxifie vers upstream sélectionné
      │ Retry sur autre upstream si erreur réseau
      ▼
[20] ResponseMiddleware               ← NOUVEAU v3
      │ Security headers injection (HSTS, X-Frame-Options, etc.)
      │ Response sanitization (supprimer Server:, X-Powered-By:)
      │ Error masking (5xx avec stack traces)
      │ Honeypot HTML injection (text/html uniquement)
      ▼
[21] ResponseLogger
      │ Log JSON SecurityEvent complet
      │ Trigger webhooks asynchrones si event match un trigger configuré
      ▼
RÉPONSE → CLIENT
```

## Nouveaux packages Go (v3)

```
internal/
├── slowloris/
│   ├── guard.go           # net.Conn wrapper avec read timeout et rate check
│   └── limiter.go         # max connexions par IP (atomic counter map)
├── assets/
│   └── bypass.go          # Détection assets statiques (extension, path prefix)
├── proxy/
│   ├── pool.go            # UpstreamPool, sélection selon stratégie
│   ├── health.go          # HealthChecker goroutine par upstream
│   └── retry.go           # Retry logic sur autres upstreams
├── security/
│   ├── headers.go         # Security headers injection (ResponseWriter wrapper)
│   ├── sanitize.go        # Response sanitization (Server: etc., error masking)
│   └── selfprotect.go     # Auto-protection WAF endpoints
├── alerting/
│   ├── manager.go         # Orchestration triggers, cooldown, dedup
│   ├── webhook.go         # HTTP POST avec retry exponential backoff
│   ├── slack.go           # Format Slack Incoming Webhook
│   └── discord.go         # Format Discord Embed
├── audit/
│   ├── trail.go           # Journal append-only, rotation FIFO, file writer
│   └── middleware.go      # Interception admin API pour journalisation
├── privacy/
│   ├── anonymizer.go      # Truncation IPv4 /24, IPv6 /48
│   └── retention.go       # Goroutine de purge avec TTL policy
├── tls/
│   ├── acme.go            # Let's Encrypt ACME HTTP-01/TLS-ALPN-01
│   ├── manager.go         # Cert loading, rotation, hot-reload
│   └── checker.go         # Expiry checker, alert webhook
├── maintenance/
│   └── page.go            # Serving page maintenance/erreurs custom
```

## Architecture complète des composants

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         WAF Go Application (v3 final)                       │
│                                                                             │
│  ┌─────────────────┐    ┌──────────────────────────────────────────────┐   │
│  │   TLS Terminator │    │              Middleware Pipeline             │   │
│  │  (ACME/static)  │    │  [0] Slowloris → [1] CF → [2] Whitelist →   │   │
│  │  :443 (option)  │    │  [3] Blacklist → [4] Assets Bypass →         │   │
│  └────────┬────────┘    │  [5] Geo → [6] ThreatIntel → [7] JA3 →      │   │
│           │             │  [8] RateLimit → [9] AntiBot → [10] AntiDDoS │   │
│  ┌────────▼────────┐    │  [11] Rules → [12] Integrity →               │   │
│  │  HTTP Server    │    │  [13] SelfProtect → [14] Trust →             │   │
│  │   :8080 (public)│───▶│  [15] Challenge → [16] Behavior →           │   │
│  └─────────────────┘    │  [17] OriginProt → [18] UpstreamPool →      │   │
│                         │  [19] ReverseProxy → [20] Response →         │   │
│  ┌─────────────────┐    │  [21] Logger + Alerting                      │   │
│  │  Admin API      │    └─────────────────────────────────────────────┘   │
│  │  :9090 (private)│                                                        │
│  │  + Audit Trail  │    ┌──────────────────────────────────────────────┐   │
│  └─────────────────┘    │           State & Intelligence               │   │
│                         │  VisitorStore (memory/redis)                  │   │
│  ┌─────────────────┐    │  BehaviorAnalyzer (ring buffers + worker)    │   │
│  │  Health Checker │    │  ThreatIntelCache (ASN mmdb + AbuseIPDB)     │   │
│  │  (goroutine/up) │    │  RulesEngine (compiled YAML)                 │   │
│  └─────────────────┘    │  UpstreamPool (health + LB)                  │   │
│                         │  AlertManager (triggers + webhooks)           │   │
│  ┌─────────────────┐    │  AuditTrail (append-only + file)             │   │
│  │  Cert Manager   │    │  PrivacyRetention (purge goroutine)          │   │
│  │  (ACME ticker)  │    └──────────────────────────────────────────────┘   │
│  └─────────────────┘                                                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Matrice de décision : Quel middleware pour quel cas ?

| Scenario | Middlewares actifs |
|----------|-------------------|
| Asset statique (.css, .js) | [0][1][2][3][4→bypass][17][18][19][20][21] |
| Visiteur connu (cookie valide, score 80) | Tous sauf [15] challenge |
| Nouveau visiteur (score 50) | Tous — [15] sert le challenge |
| IP blacklistée | [0][1][2][3→403] — stop |
| IP whitelistée | [0][1][2→bypass] — skip tout |
| Googlebot | [0][1][2→bypass par UA] — skip tout |
| Bot Slowloris | [0→ferme connexion] — stop |
| POST /waf/verify | [0][1][13][15] — pipeline challenge seulement |

## ADRs v3

- [ADR-011](decisions/ADR-011-security-headers.md) — Security Headers strategy
- [ADR-012](decisions/ADR-012-upstream-health-loadbalancing.md) — Upstream Health & LB
- [ADR-013](decisions/ADR-013-gdpr-compliance.md) — GDPR/Privacy

## Config v3 — Nouveaux blocs

```yaml
# Security headers
security_headers:
  enabled: true
  strict_transport_security: "max-age=31536000; includeSubDomains"
  x_frame_options: "SAMEORIGIN"
  x_content_type_options: "nosniff"
  referrer_policy: "strict-origin-when-cross-origin"
  permissions_policy: "geolocation=(), microphone=(), camera=()"
  content_security_policy: ""  # vide = non injecté
  x_waf_protected: "GaetanDev.fr/1.0"

# Response sanitization
sanitize_response:
  enabled: true
  remove_headers: ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"]
  server_replacement: "WAF/1.0"  # vide = supprimé
  mask_5xx_errors: true

# Slow attack protection
slow_attacks:
  headers_timeout: "10s"
  body_min_rate_bps: 100
  max_connections_per_ip: 50
  idle_read_timeout: "30s"

# Static assets bypass
static_assets:
  extensions: [".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif",
               ".webp", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"]
  path_prefixes: ["/static/", "/assets/", "/public/", "/dist/"]
  exact_paths: ["/favicon.ico", "/robots.txt", "/sitemap.xml"]

# Upstreams (pool avec health check)
upstreams:
  - address: "http://10.0.0.1:80"
    weight: 1
    label: "primary"
  - address: "http://10.0.0.2:80"
    weight: 1
    backup: true
    label: "backup"
  strategy: "round_robin"
  health_check:
    enabled: true
    path: "/health"
    interval: "10s"
    failure_threshold: 3

# Alerting
alerts:
  enabled: true
  cooldown_seconds: 60
  webhooks:
    - trigger: "ddos_detected"
      url: "https://hooks.slack.com/services/xxx"
      format: "slack"
    - trigger: "upstream_down"
      url: "https://discord.com/api/webhooks/xxx"
      format: "discord"

# Audit trail
audit:
  enabled: true
  max_entries: 10000
  file_path: ""  # vide = mémoire seulement

# Privacy / GDPR
privacy:
  anonymize_ip: false
  data_retention_hours: 24
  event_retention_hours: 24

# WAF self-protection
self_protection:
  verify_rate_limit: 10  # req/s par IP sur /waf/verify
  admin_auth_max_failures: 10
  admin_auth_window_minutes: 5

# Maintenance
maintenance:
  forced: false
  retry_after_seconds: 60
  custom_pages:
    503: "/etc/waf/maintenance/503.html"
    403: "/etc/waf/errors/403.html"
    429: "/etc/waf/errors/429.html"

# TLS (quand WAF termine TLS)
tls:
  enabled: false
  acme:
    enabled: false
    email: ""
    domains: []
    cache_dir: "/var/lib/waf/certs"
    staging: false  # true = Let's Encrypt staging
  cert_file: ""
  key_file: ""
  min_version: "1.2"
```
