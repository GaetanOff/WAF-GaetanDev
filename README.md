# WAF Anti-DDoS / Anti-Bot — GaetanDev

Reverse proxy de protection écrit en Go, conçu pour s'intercaler entre
**Cloudflare** et votre serveur d'origine :

```
 Visiteur ──▶ Cloudflare ──▶ WAF (Go) ──▶ Nginx / Origine
                              │
                              ├─ extraction IP réelle (CF-Connecting-IP)
                              ├─ whitelist / blacklist (IP, CIDR, user-agent)
                              ├─ rate limiting (token bucket par IP)
                              ├─ score de confiance par visiteur [0..100]
                              ├─ challenge JavaScript (PoW + fingerprint, sans CAPTCHA)
                              ├─ anti-bot (headless, headers, honeypot)
                              ├─ anti-DDoS (circuit breaker + mode dégradé global)
                              ├─ logs structurés (log/slog) + métriques Prometheus
                              └─ API d'administration REST (port séparé)
```

> Le projet suit une démarche **Spec-Driven Development**. Les spécifications
> dans [`specs/`](specs/) sont la source de vérité ; le code les implémente.

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Démarrage rapide](#démarrage-rapide)
- [Configuration](#configuration)
- [Référence de configuration complète](CONFIG.md)
- [Déploiement derrière Cloudflare](#déploiement-derrière-cloudflare)
- [Nginx en amont (origine)](#nginx-en-amont-origine)
- [API d'administration & métriques](#api-dadministration--métriques)
- [Développement & tests](#développement--tests)
- [Structure du projet](#structure-du-projet)

---

## Fonctionnalités

| Domaine | Détail |
|---|---|
| Reverse proxy | Routing par `Host`, multi-domaine, timeouts configurables, 502 propre si l'origine tombe |
| IP Cloudflare | `CF-Connecting-IP` utilisé **uniquement** si la source appartient aux plages CF (rejet 400 sinon) |
| Whitelist / Blacklist | IP exactes, CIDR, regex user-agent — whitelist prioritaire |
| Rate limiting | Token bucket par IP, `429 + Retry-After`, pénalité de score |
| Score de confiance | États TRUSTED / MONITORED / CHALLENGED / BLOCKED, TTL, clamp [0..100] |
| Challenge JS | Proof-of-Work SHA-256 (SubtleCrypto) + fingerprint navigateur + contrainte de timing — **aucun CAPTCHA** |
| Cookie de session | HMAC-SHA256, lié à l'IP + domaine + empreinte, TTL |
| Anti-bot | Détection headless (SwiftShader, llvmpipe), user-agents suspects, chemins honeypot |
| Anti-DDoS | Circuit breaker par IP + mode dégradé global (`503`) au-delà d'un seuil de trafic |
| Observabilité | Logs JSON corrélés (`request_id`), métriques Prometheus (`/waf/metrics`) |
| Admin | API REST Bearer sur un port séparé (CRUD whitelist/blacklist, visiteurs, stats, events) |

---

## Démarrage rapide

### Prérequis

- Go **1.26+** (pour build/dev)
- Docker + Docker Compose (pour la pile de test)

### Build & exécution locale

```bash
# Build
make build           # produit ./waf

# Secrets (jamais en clair dans le YAML)
export WAF_CHALLENGE_SECRET_KEY="<32+ caractères aléatoires>"
export WAF_ADMIN_TOKEN="<32+ caractères aléatoires>"

# Lancement avec la config d'exemple
./waf -config configs/config.example.yaml

# Vérification
curl -i http://localhost:8080/waf/health      # {"status":"ok"}
```

### Pile de test Docker (WAF + nginx d'origine)

```bash
docker compose up --build

curl -i http://localhost:8080/                 # proxifié vers l'origine nginx
curl -i http://localhost:8080/waf/health
```

La pile utilise [`deploy/config.docker.yaml`](deploy/config.docker.yaml)
(`cloudflare.trusted: false` pour permettre l'accès direct en local) et une
origine nginx minimale ([`deploy/nginx/default.conf`](deploy/nginx/default.conf)).

---

## Configuration

La configuration est un fichier YAML validé au démarrage. Référence complète :
[`configs/config.example.yaml`](configs/config.example.yaml) — schéma :
[`specs/schemas/config.schema.json`](specs/schemas/config.schema.json).

### Secrets (variables d'environnement)

Les secrets ne doivent **jamais** figurer dans le YAML. Ils sont fournis par
variables d'environnement et surchargent le fichier :

| Variable | Usage |
|---|---|
| `WAF_CHALLENGE_SECRET_KEY` | Clé HMAC du challenge et des cookies (≥ 32 caractères) |
| `WAF_ADMIN_TOKEN` | Jeton Bearer de l'API d'administration (≥ 32 caractères) |
| `WAF_REDIS_PASSWORD` | Mot de passe Redis (si backend `redis`) |

### Réglages clés

```yaml
server:
  listen: ":8080"                 # port public (derrière Cloudflare)
  admin_listen: "127.0.0.1:9090"  # API admin — NE PAS exposer publiquement

cloudflare:
  trusted: true                   # faire confiance à CF-Connecting-IP

trust:
  challenge_threshold: 40         # en dessous → challenge JS
  block_threshold: 10             # en dessous → 403

challenge:
  pow_difficulty: 16              # ~500 ms sur CPU standard
  min_elapsed_ms: 500             # trop rapide = bot
  max_elapsed_ms: 10000
```

La configuration par domaine (`domains:`) permet de surcharger upstream,
challenge, rate limit et seuils de confiance par hôte.

---

## Déploiement derrière Cloudflare

1. **DNS** : pointez votre enregistrement vers l'IP du WAF, en mode *proxied*
   (nuage orange) dans Cloudflare.
2. **TLS** : terminez le TLS sur Cloudflare (mode *Full* ou *Full (strict)*).
   Le WAF écoute en HTTP sur `:8080` côté réseau interne.
3. **Restreindre l'accès direct** : autorisez sur le pare-feu réseau uniquement
   les [plages d'IP Cloudflare](https://www.cloudflare.com/ips/) vers `:8080`.
   Le WAF rejette de toute façon (`400`) tout `CF-Connecting-IP` provenant
   d'une source hors plages Cloudflare lorsque `cloudflare.trusted: true`.
4. **IP réelle** : le WAF lit `CF-Connecting-IP` et transmet `X-Forwarded-For`
   et `X-Real-IP` à l'origine.
5. **Admin** : gardez `admin_listen` sur une interface privée (jamais publiée).

---

## Nginx en amont (origine)

Le serveur d'origine reçoit du WAF les en-têtes `X-Forwarded-For` / `X-Real-IP`.
Un exemple minimal documenté pour récupérer l'IP réelle du visiteur côté origine
est fourni dans
[`deploy/nginx/upstream.conf.example`](deploy/nginx/upstream.conf.example).

---

## API d'administration & métriques

- **Santé** : `GET /waf/health` (port public) → `{"status":"ok"}`
- **Métriques Prometheus** : `GET /waf/metrics` (port public)
- **API Admin** : port séparé (`admin_listen`), authentification `Bearer`.
  Contrat complet : [`specs/api/admin.openapi.yaml`](specs/api/admin.openapi.yaml).

```bash
curl -H "Authorization: Bearer $WAF_ADMIN_TOKEN" \
     http://127.0.0.1:9090/waf/admin/stats
```

---

## Développement & tests

```bash
make test            # go test ./...
make lint            # go vet ./...
go test ./... -race -coverprofile=coverage.out   # comme en CI
```

Les **portes qualité** (gates) sont décrites dans
[`specs/validation.md`](specs/validation.md) et exécutées en CI
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) :
lint, tests `-race` + couverture, build statique Linux, et `spectral`
sur le contrat OpenAPI.

Les comportements sont spécifiés en Gherkin dans
[`specs/features/`](specs/features/) et couverts par des tests de conformance.

---

## Structure du projet

```
cmd/waf/             point d'entrée + câblage du pipeline
internal/
  config/            chargement + validation YAML
  proxy/             reverse proxy multi-domaine
  middleware/
    cloudflare/      extraction IP réelle
    access/          whitelist / blacklist
    ratelimit/       token bucket
    antibot/         détection bots
    antiddos/        circuit breaker + mode dégradé
    challenge/       challenge JS (PoW, cookie, fingerprint)
  trust/             score de confiance
  fingerprint/       scoring des signaux navigateur
  signing/           HMAC-SHA256
  storage/           interface Store + backend mémoire
  logger/            logs structurés (log/slog, stdlib)
  metrics/           métriques Prometheus
  admin/             API d'administration REST
web/challenge.html   page de challenge (branding "Protected by GaetanDev.fr")
configs/             configuration d'exemple
deploy/              config + nginx pour docker-compose
specs/               spécifications (source de vérité, SDD)
```

---

Protected by **GaetanDev.fr** · <https://firewall.gaetandev.fr>
