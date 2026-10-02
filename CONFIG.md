# Référence de configuration — WAF GaetanDev

Ce document décrit toutes les options disponibles dans `config.yaml`.  
Le fichier d'exemple complet se trouve dans [`configs/config.example.yaml`](configs/config.example.yaml).  
Le schéma JSON (validation) est dans [`specs/schemas/config.schema.json`](specs/schemas/config.schema.json).

> **Format des durées** : toutes les valeurs de type durée utilisent la syntaxe Go —  
> ex. `"30s"`, `"5m"`, `"1h"`, `"24h"`, `"1h30m"`.

---

## Secrets — variables d'environnement

Ne mettez **jamais** de secrets dans `config.yaml`. Fournissez-les via l'environnement :

| Variable | Remplace | Longueur minimale |
|---|---|---|
| `WAF_CHALLENGE_SECRET_KEY` | `challenge.secret_key` | 32 caractères |
| `WAF_ADMIN_TOKEN` | `admin.token` | 32 caractères |
| `WAF_METRICS_AUTH_TOKEN` | `metrics.auth_token` | 32 caractères |
| `WAF_REDIS_PASSWORD` | `storage.redis.password` | — |
| `WAF_ORIGIN_SECRET` | `origin_protection.secret` | 16 caractères |
| `WAF_ABUSEIPDB_KEY` | `threat_intel.abuseipdb.api_key` | — |
| `WAF_ALERTING_WEBHOOKS_<i>_URL` | `alerting.webhooks[i].url` (index à partir de 0) | — |

L'URL d'un webhook Slack ou Discord **porte son jeton d'accès** : c'est un secret.
Déclarez l'entrée (et son `type`) dans le fichier, sans `url`, et fournissez l'URL
par `WAF_ALERTING_WEBHOOKS_<i>_URL`. Une variable ne crée pas d'entrée : elle
remplace l'URL de l'entrée `i` déclarée. Alertes actives, une entrée sans URL est
refusée au démarrage.

---

## `version`

```yaml
version: "1.0"
```

Identifiant de version du fichier de configuration. Utilisé pour la compatibilité future. Valeur obligatoire.

---

## `server` — Serveur HTTP

```yaml
server:
  listen: ":8080"
  admin_listen: "127.0.0.1:9090"
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "60s"
  graceful_shutdown_timeout: "15s"
  max_header_bytes: 65536
  strict_host: false
```

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `listen` | string | — | Adresse d'écoute du port public (trafic entrant depuis Cloudflare). Ex : `":8080"`, `"0.0.0.0:443"`. **Obligatoire.** |
| `admin_listen` | string | `"127.0.0.1:9090"` | Adresse d'écoute de l'API d'administration (HTTP clair, jeton `Bearer`). **Ne jamais exposer publiquement.** Boucle locale par défaut ; dans un conteneur, la lier explicitement à l'interface du réseau interne (ex. `0.0.0.0:9090` sans publier le port). |
| `read_timeout` | durée | `"30s"` | Délai max pour lire la requête entière (headers + body). Protège contre les connexions lentes (Slowloris). |
| `write_timeout` | durée | `"30s"` | Délai max pour envoyer la réponse complète au client, **streaming compris** : un téléchargement ou un flux (SSE, long polling) plus long que ce délai est coupé. L'augmenter pour une origine qui sert de tels contenus. Les WebSockets n'y sont pas soumis (l'échéance est levée à l'upgrade). |
| `idle_timeout` | durée | `"60s"` | Délai max d'inactivité sur une connexion keep-alive avant fermeture. |
| `max_header_bytes` | int | `65536` | Taille maximale des en-têtes d'une requête (64 Kio). Au-delà : `431`, avant tout middleware. `0` = défaut Go (1 Mio) ; sinon entre `4096` et `1048576`. |
| `graceful_shutdown_timeout` | durée | `"15s"` | Délai accordé aux connexions en cours pour se terminer proprement lors d'un arrêt (SIGTERM). |
| `strict_host` | bool | `false` | Répond `400` (`X-WAF-Reason: host_not_declared`) à toute requête dont le `Host` ne correspond à aucune entrée [`domains`](#domains--configuration-par-domaine), `/waf/health` excepté ([ADR-020](specs/decisions/ADR-020-host-header-routing-trust.md)). Exige au moins une entrée `domains[]`. `/waf/metrics` n'est **pas** exempté : un scraper Prometheus doit alors présenter un `Host` déclaré. **Opt-in** : activé, il coupe l'accès par IP. |

### `server.tls` — Terminaison TLS par domaine (SNI)

```yaml
server:
  tls:
    enabled: false
    listen: ":443"
    min_version: "1.2"
    cipher_suites: []
    redirect_http: true
    cert_file: ""        # certificat par défaut (optionnel)
    key_file: ""
```

Quand `enabled: true`, le WAF **termine lui-même le TLS** et présente le
certificat correspondant au domaine demandé (**SNI**), défini par
`domains[].tls` (voir plus bas). À utiliser quand le WAF n'est **pas** derrière
un terminateur TLS amont (Cloudflare, LB). Mutuellement exclusif avec `acme`
sur le même listener.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Terminer le TLS sur le WAF. Si `false`, le WAF écoute en HTTP (TLS terminé en amont). |
| `listen` | string | `":443"` | Adresse d'écoute HTTPS. |
| `min_version` | string | `"1.2"` | Version TLS minimale : `"1.2"` ou `"1.3"`. Les versions inférieures sont refusées. |
| `cipher_suites` | liste | `[]` | Liste explicite de cipher suites (TLS 1.2). Vide = défaut sécurisé de Go. Un nom inconnu/non sûr fait échouer le démarrage. |
| `redirect_http` | bool | `true` | Rediriger le trafic HTTP (`server.listen`) vers HTTPS en `301`. `server.listen` doit alors différer de `server.tls.listen` (refusé à la validation sinon). |
| `cert_file` | string | `""` | Certificat PEM **par défaut**, servi pour un SNI sans correspondance. Si absent, un SNI inconnu provoque un refus de handshake. |
| `key_file` | string | `""` | Clé privée PEM du certificat par défaut. |

**Fail-fast** : un certificat manquant, illisible, ou dont la clé ne correspond
pas au certificat fait **échouer le démarrage** du WAF (on ne sert jamais un
vhost cassé). La métrique `waf_tls_cert_expiry_seconds{domain}` expose la date
d'expiration (timestamp Unix) de chaque certificat chargé.

**Renouvellement** : les fichiers de certificats sont réexaminés chaque minute.
Une paire modifiée sur disque (renouvellement certbot, liens symboliques de
`live/` suivis) est rechargée et servie aux handshakes suivants, sans
redémarrage ; `waf_tls_cert_expiry_seconds` suit le nouveau certificat. Une
paire invalide au rechargement (écriture en cours, clé non concordante) est
ignorée avec un avertissement : le certificat en service est conservé et la
paire est retentée à la minute suivante. `SIGHUP` ne déclenche pas de
rechargement.

---

## `upstream` — Upstream par défaut

```yaml
upstream:
  address: "http://nginx:80"
  timeout: "30s"
  tls_verify: true
  max_idle_conns: 100
```

Upstream utilisé quand aucune entrée `domains` ne correspond au `Host` de la requête.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `address` | string | — | URL complète de l'upstream. Ex : `"http://nginx:80"`, `"https://10.0.0.1:443"`. **Obligatoire.** |
| `timeout` | durée | `"30s"` | Délai max pour recevoir la réponse de l'upstream (connect + read). |
| `tls_verify` | bool | `true` | Vérifier le certificat TLS de l'upstream. Mettre à `false` uniquement en dev avec des certificats auto-signés. |
| `max_idle_conns` | int | `100` | Taille du pool de connexions HTTP keep-alive vers l'upstream. Augmenter si l'upstream reçoit un trafic soutenu élevé. |
| `preserve_host` | bool | `false` | Conserver l'en-tête `Host` entrant vers l'upstream au lieu de le réécrire vers l'hôte de l'upstream. **Indispensable quand l'upstream route par vhost** (`server_name` nginx/OpenResty en aval). `false` = comportement historique (Host = hôte upstream). |

---

## `cloudflare` — Intégration Cloudflare

```yaml
cloudflare:
  trusted: true
  auto_update_ranges: false
  update_interval: "24h"
```

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `trusted` | bool | `true` | Faire confiance au header `CF-Connecting-IP` pour extraire la vraie IP du visiteur. Ne s'applique que si la requête provient d'une IP Cloudflare connue — sinon le header est ignoré et la requête est rejetée avec un 400. Mettre à `false` si le WAF n'est **pas** derrière Cloudflare. |
| `auto_update_ranges` | bool | `false` | Récupérer les plages IP Cloudflare depuis `https://www.cloudflare.com/ips-v4` et `ips-v6` (HTTPS uniquement) au démarrage puis toutes les `update_interval`. **Exige `trusted: true`** — les plages ne servent qu'à valider `CF-Connecting-IP`, la combinaison inverse est refusée au démarrage. |
| `update_interval` | durée | `"24h"` | Fréquence de rafraîchissement des plages IP. **Minimum `1m`** quand `auto_update_ranges: true` : les listes officielles changent quelques fois par an, un intervalle plus court ne rafraîchit rien et martèle une dépendance externe depuis chaque instance. |

**Ce que fait le rafraîchissement, exactement** :

- La liste compilée dans le binaire (relevée le 2026-06-04) sert de valeur
  initiale **et de repli permanent**. Elle n'est jamais remplacée par une liste
  partielle : les deux familles (IPv4 + IPv6) doivent être récupérées et valides.
- Une liste récupérée est **rejetée en entier** si un préfixe n'est pas canonique,
  si un préfixe est plus large que `/8` (IPv4) ou `/19` (IPv6), si une famille est
  incohérente avec sa source, si le nombre de préfixes sort des bornes de
  plausibilité (≥ 4 par famille, ≤ 512 au total) ou si le corps de réponse
  dépasse 64 KiB. Sur rejet, la liste en vigueur est **conservée**.
- Ce garde-fou n'est pas cosmétique : la liste décide quelles sources ont le droit
  de poser `CF-Connecting-IP`, donc quelle IP le WAF croit pour **toutes** ses
  décisions ensuite. Un `0.0.0.0/0` adopté rendrait l'en-tête forgeable par
  n'importe qui.
- Un échec de récupération n'empêche **pas** le WAF de démarrer ni de servir : il
  est journalisé en `warn` et compté dans
  `waf_cloudflare_ranges_update_total{result="error"}`. Le nombre de préfixes en
  vigueur est exposé par la jauge `waf_cloudflare_ranges`.

---

## `rate_limit` — Limitation de débit par IP

```yaml
rate_limit:
  enabled: true
  requests_per_second: 50
  burst: 100
  requests_per_minute: 1000
  requests_per_hour: 10000
```

Implémente un algorithme **Token Bucket** par IP, sur **trois fenêtres**
indépendantes (seconde, minute, heure). Les IPs en whitelist sont exemptées.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active/désactive le rate limiting global. |
| `requests_per_second` | float | `50` | Tokens ajoutés au bucket par seconde (débit moyen autorisé). |
| `burst` | int | `100` | Capacité maximale du bucket de la fenêtre seconde. Permet d'absorber un pic de trafic soudain sans déclencher immédiatement le 429. |
| `requests_per_minute` | int | `1000` | Limite sur la fenêtre minute. Bucket dédié : recharge = `limite / 60 s`, capacité = la limite. `0` **désactive** la fenêtre. |
| `requests_per_hour` | int | `10000` | Limite sur la fenêtre heure. Bucket dédié : recharge = `limite / 3600 s`, capacité = la limite. `0` **désactive** la fenêtre. Doit être **≥ `requests_per_minute`** quand les deux sont actives (sinon la fenêtre minute est inatteignable — refusé au démarrage). |

**Comment les trois fenêtres se combinent** :

- Une requête n'est admise que si les trois fenêtres actives disposent d'un jeton.
- Un refus par une fenêtre **ne consomme pas** le jeton des autres : un client buté
  sur sa limite horaire retrouve son burst à la seconde intact dès la réouverture.
- `burst` ne s'applique qu'à la fenêtre seconde : c'est elle qui borne la
  **rafale**. Les fenêtres minute et heure bornent le **débit soutenu** — c'est
  elles qui attrapent le martèlement lent, invisible pour une limite par seconde.
- Le resserrement sous pression globale ([FR-08](#antiddos--protection-anti-ddos-globale))
  s'applique au débit de recharge des trois fenêtres.

Quand une limite est atteinte : **HTTP 429** avec header `Retry-After` (le délai
de la fenêtre qui rouvre **le plus tard**) + pénalité de score de confiance (-10).
Le `reason` journalisé nomme la fenêtre qui a refusé — `rate_limit_exceeded`
(seconde), `rate_limit_exceeded_minute`, `rate_limit_exceeded_hour` — sans quoi
un opérateur ne peut pas savoir quelle limite règle son trafic.

> **Changement de comportement (phase 15, 2026-09-02)** : `requests_per_minute` et
> `requests_per_hour` étaient documentées mais **jamais appliquées** ; seule la
> fenêtre seconde existait. Elles le sont désormais. Avec les défauts
> (`50 req/s`, `1000 req/min`), le débit soutenu autorisé passe de 3000 à 1000
> requêtes par minute et par IP. Relevez ces valeurs — ou passez-les à `0` — si
> votre trafic légitime dépassait ce plafond.

---

## `antiddos` — Protection Anti-DDoS globale

```yaml
antiddos:
  enabled: true
  global_requests_per_second: 50000
  global_window: "1s"
  pressure_levels:
    elevated_multiplier: 1
    high_multiplier: 2
    critical_multiplier: 4
  retry_after_seconds: 5
  under_attack:
    enabled: true
    scope: "per_domain"
    trigger_pressure: "high"
    exit_pressure: "elevated"
    cooldown: "30s"
    shadow: false
    max_tracked_domains: 1024
    challenge_non_browser: false
```

Compteur global (toutes IPs confondues) utilisé pour calculer un **niveau de pression adaptative**. La pression globale ne bloque pas le trafic à elle seule : elle sert de signal pour renforcer les mitigations réversibles (challenge, throttling, difficulté PoW) et pour alimenter le moteur de risque.

Niveaux de pression :

| Niveau | Condition par défaut | Effet attendu |
|---|---|---|
| `normal` | < `global_requests_per_second` | Comportement normal. |
| `elevated` | >= `global_requests_per_second × elevated_multiplier` | Friction accrue pour visiteurs inconnus ou suspects. |
| `high` | >= `global_requests_per_second × high_multiplier` | Challenge/throttling plus fréquents, PoW plus difficile. |
| `critical` | >= `global_requests_per_second × critical_multiplier` | Mitigations réversibles maximales pour inconnus/suspects ; visiteurs connus favorisés s'ils restent sous leurs limites par IP. |

Le WAF **ne doit pas** retourner HTTP 503 ou HTTP 403 uniquement parce que le trafic global dépasse un seuil. Les blocages durs restent réservés aux contrôles explicites : blacklist, honeypot, circuit-breaker par IP, threat intel critique, JA3 blacklisté, ou score de risque corroboré.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active le calcul de pression globale anti-DDoS. |
| `global_requests_per_second` | int | `50000` | Baseline de requêtes/seconde (toutes IPs) utilisée pour calculer la pression. À ajuster selon la capacité réelle du WAF et de l'upstream. |
| `global_window` | durée | `"1s"` | Fenêtre glissante du compteur global. |
| `pressure_levels.elevated_multiplier` | float | `1` | Multiplicateur du seuil global à partir duquel la pression devient `elevated`. |
| `pressure_levels.high_multiplier` | float | `2` | Multiplicateur du seuil global à partir duquel la pression devient `high`. |
| `pressure_levels.critical_multiplier` | float | `4` | Multiplicateur du seuil global à partir duquel la pression devient `critical`. |
| `retry_after_seconds` | int | `5` | Valeur par défaut du header `Retry-After` pour les réponses volumétriques explicites par IP. La pression globale seule ne doit pas produire de 503. |

### `antiddos.under_attack` — Mode « sous attaque » (FR-39, ADR-018)

Levier de **délestage** contre un flood applicatif (L7) **distribué** : un flood
où chaque requête paraît propre (UA réaliste, `GET /`) et chaque IP reste sous sa
limite passe sous le palier `CHALLENGE` du moteur de risque et sature l'origine. Le
mode sous attaque, déclenché par la **pression** (évaluée **par domaine** par
défaut), **force le challenge JS** de toute requête **sans clearance**. La preuve de
travail filtre le botnet (incapable d'exécuter du JS) ; un navigateur réel la résout
une fois, obtient un cookie `waf_session`, puis passe sans friction. C'est une
mitigation **réversible** : elle ne produit jamais de blocage dur à elle seule.

Une requête est **avec clearance** (donc épargnée) si elle présente : un cookie
`waf_session` valide, un bot vérifié par reverse-DNS forward-confirm (FR-36), une IP
whitelistée (FR-04), ou un trust persistant « sticky » après challenge réussi
(FR-37). Un User-Agent de `whitelist_user_agents` n'est **pas** une clearance. Les
clients **non-navigateurs** (`Accept: application/json`, méthode non GET/HEAD) ne
reçoivent pas de page JS insoluble : ils sont plafonnés à `THROTTLE` (débit de
recharge du rate limit réduit de moitié, 429 neutre `rate_limit_under_attack`) et
restent soumis au moteur de risque. Ce plafond est **par IP** : un flood distribué
qui envoie `Accept: application/json` y échappe. Sur un domaine sans client API,
activer `challenge_non_browser` pour challenger aussi ces requêtes.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active le mode sous attaque. |
| `scope` | enum | `"per_domain"` | `per_domain` circonscrit le mode au domaine attaqué ; `global` l'applique à tout le trafic. |
| `trigger_pressure` | enum | `"high"` | Niveau de pression (`elevated`/`high`/`critical`) déclenchant l'entrée en mode sous attaque. |
| `exit_pressure` | enum | `"elevated"` | Plancher d'hystérésis : le mode n'est quitté que sous ce niveau, maintenu pendant `cooldown`. Doit être `<= trigger_pressure`. |
| `cooldown` | durée | `"30s"` | Durée pendant laquelle la pression doit rester sous `exit_pressure` avant de quitter le mode (anti-battement). |
| `shadow` | bool | `false` | `true` = calcule et journalise `under_attack` **sans** forcer le challenge (calibration, FR-38). |
| `max_tracked_domains` | int | `1024` | Plafond LRU du nombre de domaines suivis (scope `per_domain`). |
| `challenge_non_browser` | bool | `false` | `true` = challenge aussi les requêtes non-navigateur sans clearance (méthode non GET/HEAD, `Accept: application/json`). Casse les clients API pendant l'attaque : à réserver aux déploiements sans API. |

> **Réglage.** `trigger_pressure` se calcule à partir de `global_requests_per_second`
> et des `pressure_levels`. Pour une petite infra, abaisser `global_requests_per_second`
> à la capacité réelle de l'upstream (ex. ~150) de sorte qu'un flood de quelques
> centaines de req/s atteigne `high`. Déployer d'abord en `shadow: true` ≥ 24 h pour
> mesurer le taux de faux positifs avant enforcement (NFR-15).

---

## `trust` — Système de confiance visiteur

```yaml
trust:
  initial_score: 50
  challenge_threshold: 40
  block_threshold: 10
  score_ttl: "1h"
  max_visitors: 100000
```

Chaque visiteur (identifié par le hash de son IP) se voit attribuer un score de confiance entre 0 et 100. Ce score évolue dynamiquement selon son comportement.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `initial_score` | int [0–100] | `50` | Score attribué à un nouveau visiteur jamais vu. |
| `challenge_threshold` | int [0–100] | `40` | Score en dessous duquel le challenge JavaScript est déclenché. |
| `block_threshold` | int [0–100] | `10` | Score en dessous duquel le visiteur est bloqué (HTTP 403). Doit être strictement inférieur à `challenge_threshold`. |
| `score_ttl` | durée | `"1h"` | Durée de vie d'un score visiteur inactif. Après expiration, le visiteur repart avec `initial_score`. |
| `max_visitors` | int | `100000` | Taille maximale du cache de scores (LRU). Les visiteurs les moins récents sont évincés au-delà de cette limite. |

**Évolution du score** (valeurs fixes internes) :

| Événement | Variation |
|---|---|
| Challenge JS réussi | +25 |
| Challenge JS échoué | -20 |
| Rate limit atteint | -10 |
| User-agent suspect | -15 |
| Pattern bot détecté | -30 |
| Honeypot déclenché | → 0 immédiat, puis ban pendant `score_ttl` |

La « navigation normale (+1 par requête) » n'existe pas : la confiance croîtrait avec le volume de requêtes, qu'un bot maîtrise.

---

## `risk_engine` — Moteur de risque multi-signaux

```yaml
risk_engine:
  enabled: true
  profile: "balanced"
  fusion: "diluted"
  shadow_mode: true
  # Absents : valeurs du profil. Une clé explicite prime (poids par poids).
  # tiers: { block: 95 }
  # weights: { geo: 0 }
  human_credit:
    challenge_passed: -40
    stable_fingerprint: -15
    sticky_trust_ttl: "30m"
  verified_bots:
    enabled: true
    success_cache_ttl: "12h"
    failure_cache_ttl: "10m"
    crawlers:
      - "googlebot"
```

Le moteur de risque fusionne plusieurs familles de signaux pour calculer un **score de risque composite** [0–100] et décider d'une action.

`tiers`, `weights`, `block_min_confidence`, `min_corroborating_families` et `family_corroboration_threshold` prennent la valeur du **profil** quand ils sont absents (ou à 0) ; une valeur explicite prime, poids par poids pour `weights`. Les défauts des tableaux ci-dessous sont ceux du profil `balanced`. Ces clés étaient auparavant pré-remplies avec les valeurs `balanced` et écrasaient le profil : `profile: strict` ou `lenient` était sans effet. Une configuration qui les fixe toutes neutralise encore le profil.

| Clé | lenient | balanced | strict |
|---|---|---|---|
| `tiers` (observe/throttle/challenge/tarpit/block) | 35/55/75/88/96 | 25/45/65/80/90 | 15/35/55/72/85 |
| `block_min_confidence` | 0.75 | 0.6 | 0.5 |
| `family_corroboration_threshold` | 60 | 50 | 45 |
| `weights` reputation/behavioral/tls/fingerprint/integrity/rate/geo/human_credit | 0.6/0.7/0.5/0.7/0.9/0.3/0.2/3.0 | 1.0/1.0/0.8/1.0/1.2/0.6/0.5/1.0 | 1.8/1.5/1.2/1.5/1.6/1.0/0.8/0.5 |

**Mode de fusion** (`fusion`) :

- `diluted` (défaut, historique) : la somme pondérée est divisée par la somme de **tous** les poids. Sept familles à 100 donnent 86, un scanner réaliste (réputation 60, intégrité 100, rate 80) 32 : un `BLOCK` heuristique est inatteignable avec les paliers par défaut, seuls les déclencheurs déterministes (blacklist, honeypot, JA3, threat intel critique, circuit-breaker) bloquent en pratique.
- `available` : la somme est divisée par la somme des poids des seules familles qui portent une évidence, et la réputation est neutre au score initial (`(initial_score - score) × 100 / initial_score`) — un nouveau visiteur obtient 0, ce même scanner (trust 30) 74 (`CHALLENGE`). Les heuristiques deviennent effectives : « assets absents » se déclenche dès qu'un CDN met les assets en cache et « intervalles réguliers » touche tout polling d'API. **Activer après au moins 24 h en `shadow_mode: true`**, en observant `waf_decisions_total{tier}`.

### Options principales

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active le moteur de risque. Si désactivé, seul le système de confiance `trust` est utilisé. |
| `profile` | string | `"balanced"` | Profil de sensibilité global. `lenient` : moins de faux positifs, moins de protection. `balanced` : équilibre recommandé. `strict` : plus agressif, risque accru de faux positifs. Fournit les clés absentes ci-dessous. |
| `fusion` | string | `"diluted"` | Mode de fusion : `diluted` ou `available` (voir ci-dessus). |
| `shadow_mode` | bool | `true` | **Mode calibration.** Le moteur calcule et journalise ses décisions sans les appliquer. Permet d'observer les faux positifs avant d'activer le blocage réel. **Passer à `false` après au moins 24h d'observation.** Il s'applique aussi aux blocages heuristiques de l'anti-bot, mais seulement moteur actif : avec `enabled: false`, il est sans effet. |
| `block_min_confidence` | float [0–1] | `0.6` | Niveau de confiance minimum (score interne) pour qu'un blocage soit effectif. Évite les blocages sur des signaux trop faibles. |
| `min_corroborating_families` | int | `2` | Nombre minimum de familles de signaux différentes qui doivent dépasser le seuil pour déclencher une action. Évite de bloquer sur un seul signal isolé. |
| `family_corroboration_threshold` | int [0–100] | `50` | Score individuel qu'une famille doit dépasser pour être considérée comme « corroborante ». |

### `risk_engine.tiers` — Seuils d'action

Les seuils doivent être **strictement croissants** (observe < throttle < challenge < tarpit < block).

| Clé | Défaut | Action déclenchée au-dessus du seuil |
|---|---|---|
| `observe` | `25` | Log renforcé, pas de blocage. |
| `throttle` | `45` | Ralentissement de la requête. |
| `challenge` | `65` | Challenge JavaScript déclenché. |
| `tarpit` | `80` | Réponse tarpit (débit en goutte à goutte pour épuiser le bot). |
| `block` | `90` | Blocage HTTP 403 immédiat. |

### `risk_engine.weights` — Poids des familles de signaux

Chaque famille contribue au score composite, pondérée par son poids. Mettre un poids à `0` désactive la famille sans toucher aux autres.

| Famille | Défaut | Ce qu'elle mesure |
|---|---|---|
| `reputation` | `1.0` | Réputation de l'IP (threat intel, blacklists). |
| `behavioral` | `1.0` | Anomalies comportementales (vitesse, patterns de navigation). |
| `tls` | `0.8` | Fingerprint TLS / JA3 suspect ou changement de fingerprint. |
| `fingerprint` | `1.0` | Cohérence du fingerprint navigateur (canvas, audio, etc.). |
| `integrity` | `1.2` | Anomalies dans les headers, le path, le body (injection, obfuscation). |
| `rate` | `0.6` | Dépassement des limites de débit. |
| `geo` | `0.5` | Géolocalisation (pays bloqués ou à risque). |
| `human_credit` | `1.0` | Crédit humain (challenge passé, fingerprint stable). |

### `risk_engine.human_credit` — Crédit humain

Récompense les visiteurs qui prouvent leur nature humaine, en réduisant leur score de risque.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `challenge_passed` | int | `-40` | Réduction du score de risque quand le challenge JS est réussi (valeur négative). |
| `stable_fingerprint` | int | `-15` | Réduction du score si le fingerprint navigateur est identique entre les sessions. |
| `sticky_trust_ttl` | durée | `"30m"` | Durée pendant laquelle le crédit humain est maintenu sans nouvelle preuve. |

### `risk_engine.verified_bots` — Bots légitimes vérifiés

Vérifie que les bots déclarant être Googlebot, Bingbot, etc. le sont vraiment (reverse DNS lookup).

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active la vérification des bots légitimes. |
| `success_cache_ttl` | durée | `"12h"` | Durée de mise en cache d'une vérification réussie (évite de re-vérifier à chaque requête). |
| `failure_cache_ttl` | durée | `"10m"` | Durée de mise en cache d'un échec de vérification. |
| `crawlers` | liste | `["googlebot", "bingbot", "duckduckbot", "applebot", "slurp", "baiduspider"]` | Liste de sous-chaînes de user-agents à vérifier. La comparaison est insensible à la casse. Seuls ces six crawlers ont un domaine reverse-DNS connu ; un autre nom reste `spoofed`. |

---

## `integrity` — Analyse d'intégrité des requêtes

```yaml
integrity:
  enabled: true
  max_body_bytes: 10485760   # 10 MB
  max_path_length: 2048
  max_query_length: 4096
```

Détecte les requêtes malformées ou suspectes : chemins trop longs, bodies trop lourds, tentatives d'injection ou d'obfuscation.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active l'analyse d'intégrité. |
| `max_body_bytes` | int | `10485760` | Taille maximale du body acceptée (en octets). 10 485 760 = 10 MB. Les requêtes plus lourdes reçoivent un HTTP 413. |
| `max_path_length` | int | `2048` | Longueur maximale du chemin URL (sans la query string). Les chemins plus longs reçoivent un HTTP 414. |
| `max_query_length` | int | `4096` | Longueur maximale de la query string. |

---

## `behavioral` — Analyse comportementale

```yaml
behavioral:
  enabled: true
  max_records: 50
```

Analyse les N dernières requêtes d'un visiteur pour détecter des patterns anormaux : vitesse excessive, scraping, credential stuffing, etc.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active l'analyse comportementale. |
| `max_records` | int | `50` | Nombre de requêtes conservées par visiteur pour l'analyse. Plus la valeur est haute, plus la détection est précise mais plus la mémoire consommée est importante. |

---

## `threat_intel` — Threat Intelligence

```yaml
threat_intel:
  enabled: false
  cache_ttl: "1h"
  blocklist_cidrs:
    - "198.51.100.0/24"
  suspect_cidrs:
    - "203.0.113.0/24"
  abuseipdb:
    enabled: false
    url: "https://api.abuseipdb.com/api/v2/check"
    api_key: ""
```

Consulte des listes de réputation IP (locales ou via l'API AbuseIPDB) pour enrichir le score de risque.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Active le module threat intel. Nécessite au moins une source (listes locales ou AbuseIPDB). |
| `cache_ttl` | durée | `"1h"` | Durée de mise en cache des résultats de lookup. Évite de re-interroger la même IP à chaque requête. Un lookup dont une source n'a pas répondu (erreur, timeout, quota) n'est gardé qu'une minute. |
| `blocklist_cidrs` | liste | `[]` | Plages CIDR considérées comme **malveillantes** → verdict `malicious` → trust score plafonné à 20. |
| `suspect_cidrs` | liste | `[]` | Plages CIDR considérées comme **suspectes** (Tor, datacenter, VPN) → verdict `suspect` → trust score plafonné à 35. |
| `abuseipdb.enabled` | bool | `false` | Active la consultation de l'API AbuseIPDB en complément des listes locales. |
| `abuseipdb.url` | string | URL AbuseIPDB | URL de l'endpoint AbuseIPDB. Ne pas modifier sauf si vous utilisez un proxy interne. |
| `abuseipdb.api_key` | string | `""` | Clé API AbuseIPDB. **Préférer la variable d'environnement `WAF_ABUSEIPDB_KEY`.** |

Score AbuseIPDB ≥ 80 : déclencheur déterministe `threat_intel_critical` (403) ; ≥ 50 : trust score plafonné à 20. Le lookup est asynchrone : la première requête d'une IP inconnue est traitée comme « propre ». Un `429` d'AbuseIPDB (quota du plan gratuit : 1 000 requêtes par jour) suspend les appels jusqu'à son `Retry-After` (1 h à défaut, 24 h au plus) ; les plages locales restent évaluées.

---

## `adaptive` — Difficulté PoW adaptative

```yaml
adaptive:
  enabled: true
  max_difficulty: 20
  decay_tau: "5m"
```

Ajuste dynamiquement la difficulté du challenge Proof-of-Work selon l'intensité de l'attaque. Sous attaque forte, la difficulté monte jusqu'à `max_difficulty`. Elle redescend progressivement selon `decay_tau` quand le trafic se normalise.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active l'adaptation automatique de la difficulté PoW. |
| `max_difficulty` | int [8–24] | `20` | Plafond de bits de difficulté. Une PoW de `n` bits coûte en moyenne `2ⁿ` hachages SHA-256 : 20 bits ≈ 0,4 s sur un poste récent et 2 à 4 s sur un mobile ; 24 bits ≈ 6,5 s sur poste et 35 à 55 s sur mobile, au-delà de `challenge.token_ttl` (30 s) — les mobiles boucleraient sur `token_expired`. Doit être ≥ `challenge.pow_difficulty`. Une valeur au-delà de 24 est refusée au démarrage. |
| `decay_tau` | durée | `"5m"` | Constante de temps du retour à la normale (décroissance exponentielle). Avec `5m`, la difficulté revient à ~37% de son pic après 5 minutes. |

---

## `geo` — Règles géographiques

```yaml
geo:
  enabled: false
  allowed_countries: []
  blocked_countries: []
  challenge_countries: []
  challenge_contribution: 60
```

Filtrage basé sur le pays d'origine, fourni par le header `CF-IPCountry` de Cloudflare. Si ce header est absent, les règles géo sont ignorées.

> **Frontière de confiance** ([ADR-019](specs/decisions/ADR-019-infrastructure-header-trust.md)) :
> `CF-IPCountry` n'est honoré que sur une connexion issue d'une plage Cloudflare
> avec `cloudflare.trusted: true` ; sinon il est supprimé à l'entrée. Avec
> `cloudflare.trusted: false`, le filtrage géographique n'a donc aucune entrée
> (avertissement au démarrage). Un client qui joint le WAF **hors Cloudflare**
> obtient le même résultat en omettant l'en-tête : tant que l'origine est
> joignable directement, ces règles réduisent le bruit mais ne sont pas une
> frontière de sécurité.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Active le filtrage géographique. **Opt-in.** |
| `allowed_countries` | liste | `[]` | Codes pays ISO 3166-1 alpha-2 autorisés. Si non vide, tout pays absent de la liste reçoit un HTTP 403 (mode whitelist). Ex : `["FR", "BE", "CH"]`. |
| `blocked_countries` | liste | `[]` | Codes pays systématiquement bloqués (HTTP 403). S'applique même si la liste `allowed_countries` est vide. |
| `challenge_countries` | liste | `[]` | Codes pays qui déclenchent une contribution de risque renforcée (sans blocage direct). |
| `challenge_contribution` | int [0–100] | `60` | Valeur ajoutée au score de risque pour les pays listés dans `challenge_countries`. |

---

## `tls_fingerprint` — Fingerprinting TLS / JA3

```yaml
tls_fingerprint:
  enabled: true
  ja3_header: "Cf-Bot-Management-Ja3Hash"
  ja3_blacklist: []
  swap_contribution: 50
```

Le hash JA3 est une empreinte du client TLS (version, ciphers, extensions). Il est lu depuis le header Cloudflare Bot Management — le WAF ne déchiffre pas le TLS lui-même.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active le fingerprinting TLS. |
| `ja3_header` | string | `"Cf-Bot-Management-Ja3Hash"` | Nom du header HTTP fourni par Cloudflare contenant le hash JA3. Ne pas modifier sauf si votre proxy utilise un header différent. Un en-tête `CF-*` n'est honoré que venant d'une plage Cloudflare avec `cloudflare.trusted: true` ([ADR-019](specs/decisions/ADR-019-infrastructure-header-trust.md)) ; un en-tête hors espace `CF-` n'est **pas** vérifié et reste forgeable. |
| `ja3_blacklist` | liste | `[]` | Hashes JA3 bloqués **de manière déterministe** (sans passer par le moteur de risque). Utile pour bloquer des outils d'attaque connus dont le fingerprint TLS est public. |
| `swap_contribution` | int [0–100] | `50` | Contribution ajoutée au score de risque si le fingerprint JA3 change entre deux sessions d'un même visiteur (comportement typique de certains scanners). |

---

## `deception` — Couche de déception (Tarpit)

```yaml
deception:
  enabled: true
  tarpit_max_connections: 500
  tarpit_chunks: 20
  tarpit_chunk_delay: "1s"
```

Les visiteurs classés **TARPIT** par le moteur de risque reçoivent une fausse réponse HTML envoyée en petits morceaux avec un délai artificiel. L'objectif est d'immobiliser les ressources du bot sans le bloquer explicitement.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active le tarpit. |
| `tarpit_max_connections` | int | `500` | Nombre maximum de connexions tarpitées simultanément. Au-delà, les nouvelles connexions TARPIT reçoivent un 503 immédiat pour protéger les ressources du WAF. |
| `tarpit_chunks` | int | `20` | Nombre de fragments HTML envoyés avant de fermer la connexion. |
| `tarpit_chunk_delay` | durée | `"1s"` | Délai entre chaque fragment. Avec 20 chunks à 1s chacun, un bot reste immobilisé ~20 secondes. |

---

## `rules` — Règles personnalisées

```yaml
rules:
  enabled: false
  file: ""
```

Moteur de règles DSL YAML pour définir des politiques de filtrage personnalisées (basées sur headers, paths, méthodes, etc.).

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Active le moteur de règles. **Opt-in.** |
| `file` | string | `""` | Chemin vers le fichier YAML de règles, lu **au démarrage** (pas de rechargement à chaud à ce jour). **Obligatoire si `enabled: true`.** Syntaxe : `specs/schemas/rule.schema.json` ; le décodage est strict et une action, un champ ou une clé non supportés font échouer le démarrage. |

---

## `origin_protection` — Protection de l'origine

```yaml
origin_protection:
  enabled: false
  # secret: "change-me-min-16-chars"  # Préférer WAF_ORIGIN_SECRET
```

Injecte un token HMAC rotatif dans les requêtes vers l'upstream. L'upstream peut vérifier ce token pour s'assurer que les requêtes passent bien par le WAF (empêche le bypass direct).

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Active la protection d'origine. **Opt-in.** |
| `secret` | string | `""` | Clé HMAC partagée entre le WAF et l'upstream (≥ 16 caractères). **Utiliser `WAF_ORIGIN_SECRET`.** |

---

## `cluster` — Synchronisation multi-nœuds

```yaml
cluster:
  enabled: false
  channel: "waf:events"
```

Synchronise les décisions (ajouts et retraits de blacklist par l'API admin, ouverture de circuit, score critique) entre plusieurs instances WAF via Redis Pub/Sub, sur la connexion `storage.redis` (quel que soit `storage.backend`).

Chaque événement est signé (HMAC-SHA256, clé dérivée de `challenge.secret_key`) : un message non signé, mal signé ou de type inconnu est ignoré et compté dans `waf_cluster_rejected_events_total`. Tous les nœuds doivent donc partager le même `challenge.secret_key` (`WAF_CHALLENGE_SECRET_KEY`). Chaque événement porte aussi son instant d'émission, signé : un événement à plus de 2 minutes de l'horloge du récepteur est ignoré (rejeu d'un message capturé). Les nœuds doivent avoir des horloges synchronisées (NTP) ; pendant une mise à jour progressive, les événements des nœuds pas encore à jour (sans horodatage) sont ignorés. Un rejeu reste possible dans la fenêtre de 2 minutes : garder Redis sur un réseau privé, avec mot de passe, TLS et une ACL qui réserve `PUBLISH`/`SUBSCRIBE` sur le canal aux nœuds WAF. Un retrait reçu d'un autre nœud ne retire qu'une entrée ajoutée à l'exécution : une entrée de `blacklist` dans la configuration du nœud reste en place. Les listes modifiées par l'API admin ne survivent pas à un redémarrage.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Active la synchronisation cluster. **Opt-in.** Requiert `storage.redis.address` et `challenge.secret_key` (≥ 32 caractères, identique sur tous les nœuds). |
| `channel` | string | `"waf:events"` | Nom du canal Pub/Sub Redis utilisé pour diffuser les événements entre nœuds. |

---

## `security_headers` — En-têtes de sécurité HTTP

```yaml
security_headers:
  enabled: true
  hsts_max_age: 31536000
  hsts_include_subdomains: true
  frame_options: "DENY"
  content_type_nosniff: true
  referrer_policy: "strict-origin-when-cross-origin"
  permissions_policy: ""
  csp: ""
  strip_headers:
    - "Server"
    - "X-Powered-By"
```

Ajoute des headers de sécurité aux réponses et supprime les headers qui révèlent des informations sur la stack technique.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active l'injection de headers de sécurité. |
| `hsts_max_age` | int | `31536000` | Durée (secondes) de l'en-tête `Strict-Transport-Security`. `31536000` = 1 an. Mettre à `0` pour désactiver HSTS. |
| `hsts_include_subdomains` | bool | `true` | Ajoute `; includeSubDomains` à l'en-tête HSTS. |
| `frame_options` | string | `"DENY"` | Valeur de `X-Frame-Options`. `"DENY"` interdit tout iframe. `"SAMEORIGIN"` autorise l'iframe depuis le même domaine. `""` désactive le header. |
| `content_type_nosniff` | bool | `true` | Ajoute `X-Content-Type-Options: nosniff` (empêche le MIME-sniffing par le navigateur). |
| `referrer_policy` | string | `"strict-origin-when-cross-origin"` | Valeur du header `Referrer-Policy`. |
| `permissions_policy` | string | `""` | Valeur du header `Permissions-Policy`. Ex : `"camera=(), microphone=()"`. Vide = header non envoyé. |
| `csp` | string | `""` | Valeur du header `Content-Security-Policy`. **Ne pas activer sans tester** : une CSP mal configurée casse le rendu de votre site. Vide = header non envoyé. |
| `strip_headers` | liste | `["Server", "X-Powered-By"]` | Headers de réponse de l'upstream à supprimer avant de renvoyer au client (masquage de la stack). |

---

## `slowloris` — Protection Slowloris / Slow POST

```yaml
slowloris:
  enabled: true
  max_connections_per_ip: 50
  header_timeout: "10s"
```

Protège contre les attaques qui ouvrent de nombreuses connexions HTTP lentes pour épuiser les ressources serveur (FR-23). Le corps lent (Slow POST) est borné par [`server.read_timeout`](#server--serveur-http), la connexion inactive par `server.idle_timeout`.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active la borne de requêtes simultanées par IP. |
| `max_connections_per_ip` | int | `50` | Nombre maximum de **requêtes en cours** par IP réelle du visiteur (une IPv6 par son /64) — derrière Cloudflare, les connexions TCP viennent des points de présence. Au-delà : `429` (`Retry-After: 10`, `X-WAF-Reason: too_many_connections_per_ip`). S'applique à tout chemin sauf `/waf/health`, IP whitelistées comprises. |
| `header_timeout` | durée | `"10s"` | Délai maximum pour recevoir l'ensemble des en-têtes HTTP. Au-delà, la connexion est fermée **sans réponse** (pas de `408`). Le délai de `10s` s'applique aussi quand `enabled` est faux. |

---

## `static_assets` — Bypass des assets statiques

```yaml
static_assets:
  enabled: true
  extensions:
    - ".css"
    - ".js"
    - ".png"
    - ".jpg"
    # ...
  path_prefixes: ["/static/", "/assets/", "/public/", "/dist/"]
  exact_paths: ["/favicon.ico", "/robots.txt", "/sitemap.xml"]
```

Les requêtes `GET` et `HEAD` vers des assets statiques (CSS, JS, images, fonts…) ne déclenchent pas le challenge JS proactif et échappent aux décisions heuristiques (trust score, anti-bot, intégrité, score du moteur de risque). Une écriture (`POST`, `PUT`, `PATCH`, `DELETE`) vers un chemin d'asset traverse le pipeline complet : `POST /login.css` n'est pas un asset. Les contrôles déterministes et la défense volumétrique s'appliquent toujours aux assets : blacklist, géo-blocage, règles custom, threat intel, blacklist JA3, ban honeypot, rate limit, comptage de pression anti-DDoS et circuit-breaker. Sous attaque (`antiddos.under_attack`), un asset sans cookie de clearance est challengé comme une page — un navigateur qui a franchi le challenge renvoie son cookie sur chaque asset du domaine. Chaque requête bypassée est comptée dans `waf_asset_requests_total{domain}`.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active le bypass des assets statiques. |
| `extensions` | liste | Voir exemple | Extensions de fichiers bypassant le challenge. La comparaison est insensible à la casse. |
| `path_prefixes` | liste | `["/static/", "/assets/", "/public/", "/dist/"]` | Préfixes de répertoire bypassant le challenge, **quel que soit le chemin qui suit** : n'y listez que des répertoires réellement statiques. Sensible à la casse ; chaque préfixe commence et finit par `/`, `/` seul est refusé. |
| `exact_paths` | liste | `["/favicon.ico", "/robots.txt", "/sitemap.xml"]` | Chemins exacts bypassant le challenge (moteurs de recherche). Sensible à la casse. |

---

## `upstream_pool` — Pool d'upstreams avec load balancing

```yaml
upstream_pool:
  enabled: false
  strategy: "round_robin"
  upstreams:
    - address: "http://10.0.0.1:80"
      weight: 1
      backup: false
  health_check:
    path: "/healthz"
    interval: "10s"
    timeout: "2s"
    healthy_threshold: 2
    unhealthy_threshold: 3
```

Remplace l'`upstream` unique par un pool load-balancé avec health checks. **Prend la priorité sur `upstream` et `domains[].upstream`** quand activé : le pool est global et sert tous les hôtes (pas de pool par domaine). Un `domains[].upstream` différent de `upstream.address` est alors ignoré, et signalé par un avertissement au démarrage.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Active le pool d'upstreams. **Opt-in.** |
| `strategy` | string | `"round_robin"` | Stratégie de répartition. `round_robin` : tour à tour. `least_conn` : connexions les moins actives. `ip_hash` : affinité par IP client. `weighted` : selon les poids définis. |
| `upstreams[].address` | string | — | URL de l'upstream. |
| `upstreams[].weight` | int | `1` | Poids relatif (utilisé uniquement avec `strategy: "weighted"`). |
| `upstreams[].backup` | bool | `false` | Si `true`, cet upstream n'est utilisé que si tous les upstreams principaux sont hors service. |
| `health_check.path` | string | `"/healthz"` | Chemin HTTP de la sonde de santé. |
| `health_check.interval` | durée | `"10s"` | Fréquence des sondes. |
| `health_check.timeout` | durée | `"2s"` | Délai max d'une sonde avant échec. |
| `health_check.healthy_threshold` | int | `2` | Nombre de sondes réussies consécutives pour marquer un upstream comme sain. |
| `health_check.unhealthy_threshold` | int | `3` | Nombre de sondes échouées consécutives pour marquer un upstream comme hors service. Une erreur de proxy sur une requête le retire aussitôt, sans attendre ce seuil. |

> **Non implémenté à ce jour** : aucun retry d'une requête sur un autre membre
> (le client reçoit `502`, le membre est retiré pour les requêtes suivantes) ;
> quand aucun membre n'est sain, la réponse est `502 no healthy upstream` et non
> une page de maintenance ; pas d'endpoint `GET /waf/admin/upstreams`.

---

## `audit` — Journal d'audit admin

```yaml
audit:
  enabled: true
  max_entries: 1000
  file: ""
```

Enregistre toutes les actions effectuées via l'API d'administration (ajout/suppression en whitelist/blacklist, modifications de config…). Les secrets sont automatiquement masqués dans le journal.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active le journal d'audit. |
| `max_entries` | int | `1000` | Nombre maximum d'entrées conservées en mémoire (FIFO). Les entrées les plus anciennes sont supprimées au-delà. |
| `file` | string | `""` | Chemin vers un fichier d'export du journal (append-only). Vide = mémoire uniquement. |

---

## `gdpr` — Conformité RGPD

```yaml
gdpr:
  anonymize_ip: true
```

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `anonymize_ip` | bool | `true` | Anonymise les adresses IP dans les logs : IPv4 masquée au /24 (ex : `1.2.3.0`), IPv6 au /48. Le hash interne (utilisé pour la corrélation des scores) reste intact. |

**Effacement à la demande** : `POST /waf/admin/gdpr/erase` avec `{"ip": "1.2.3.4"}` supprime toutes les données associées à une IP.

---

## `alerting` — Webhooks d'alerte

```yaml
alerting:
  enabled: false
  cooldown: "5m"
  max_retries: 3
  webhooks:
    - type: "slack"
      url: "https://hooks.slack.com/services/..."
    - type: "discord"      # url fournie par WAF_ALERTING_WEBHOOKS_1_URL
```

Envoie des notifications vers Slack, Discord ou tout endpoint HTTP générique lors d'événements de sécurité : requête bloquée (`block`), circuit-breaker ouvert, honeypot, entrée et sortie du mode sous attaque. Les champs des messages Slack et Discord sont tronqués aux limites de ces plateformes (valeur de champ : 1 024 caractères).

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Active les alertes webhook. **Opt-in.** |
| `cooldown` | durée | `"5m"` | Délai minimum entre deux alertes identiques (même trigger + même domaine). Évite le flood de notifications. Le domaine est borné à `domains[]` : tout Host non déclaré partage la clé `_undeclared`, pour qu'une rotation du Host ne multiplie pas les alertes. Les transitions du mode sous attaque n'y sont pas soumises. |
| `max_retries` | int | `3` | Nombre de tentatives en cas d'échec d'envoi du webhook. |
| `webhooks[].type` | string | — | Type de webhook : `"slack"`, `"discord"`, ou `"generic"` (POST JSON brut). |
| `webhooks[].url` | string | — | URL absolue du webhook, requise quand `enabled`. Elle porte le jeton d'accès : **préférer `WAF_ALERTING_WEBHOOKS_<i>_URL`**. |

---

## `self_protection` — Auto-protection du WAF

```yaml
self_protection:
  enabled: true
  verify_max_per_minute: 60
  admin_max_failures: 5
  admin_lockout: "5m"
```

Protège les endpoints internes du WAF contre les abus.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active l'auto-protection. |
| `verify_max_per_minute` | int | `60` | Nombre maximum de requêtes `POST /waf/verify` (soumission de challenge) acceptées par IP et par minute. Protège contre le brute-force de challenge. |
| `admin_max_failures` | int | `5` | Nombre d'échecs d'authentification admin consécutifs avant verrouillage de l'IP. |
| `admin_lockout` | durée | `"5m"` | Durée du verrouillage après dépassement du nombre d'échecs admin. |

---

## `acme` — TLS automatique (Let's Encrypt)

```yaml
acme:
  enabled: false
  domains:
    - "example.com"
  email: "admin@example.com"
  cache_dir: "./certs"
  tls_listen: ":443"
  http_challenge_listen: ":80"
```

Active la terminaison TLS directe par le WAF avec renouvellement automatique des certificats via Let's Encrypt. **À n'utiliser que si le WAF n'est pas derrière Cloudflare** (qui gère lui-même le TLS).

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Active ACME / Let's Encrypt. **Opt-in.** |
| `domains` | liste | `[]` | Domaines pour lesquels obtenir des certificats. **Obligatoire si `enabled: true`.** |
| `email` | string | `""` | Email de contact pour Let's Encrypt (notifications d'expiration). |
| `cache_dir` | string | `"./certs"` | Répertoire de stockage des certificats. Doit être persistant (volume Docker si containerisé). |
| `tls_listen` | string | `":443"` | Port d'écoute HTTPS. |
| `http_challenge_listen` | string | `":80"` | Port d'écoute pour le challenge HTTP-01 de Let's Encrypt. Doit être accessible depuis Internet sur le port 80. |

---

## `maintenance` — Mode maintenance

```yaml
maintenance:
  enabled: false
  error_pages: true
```

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Passe le WAF en **mode maintenance** : toutes les requêtes, assets statiques compris, reçoivent une page 503 brandée avec `Retry-After: 300`, sauf `/waf/health` et `/waf/metrics` (sondes de monitoring). Lu au démarrage (pas de bascule par l'API admin). À activer lors d'une maintenance planifiée de l'upstream. |
| `error_pages` | bool | `true` | Remplace les corps de réponses d'erreur (4xx/5xx) en texte brut par une page HTML brandée. N'affecte pas les réponses qui ont déjà un body HTML. |

---

## `challenge` — Challenge JavaScript

```yaml
challenge:
  enabled: true
  # secret_key: "..."  # Préférer WAF_CHALLENGE_SECRET_KEY
  token_ttl: "30s"
  cookie_ttl: "24h"
  cookie_name: "waf_session"
  pow_difficulty: 16
  min_elapsed_ms: 0
  max_elapsed_ms: 60000
```

Le challenge JavaScript consiste en un Proof-of-Work SHA-256 (via `SubtleCrypto`) combiné à un fingerprint navigateur. Il n'y a aucun CAPTCHA visuel.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active le challenge JS. |
| `secret_key` | string | — | Clé HMAC pour signer les tokens de challenge et les cookies de session (≥ 32 caractères). **Utiliser `WAF_CHALLENGE_SECRET_KEY`.** |
| `token_ttl` | durée | `"30s"` | Durée de validité d'un nonce de challenge. Passé ce délai, le visiteur doit recommencer. |
| `cookie_ttl` | durée | `"24h"` | Durée de validité du cookie de session après un challenge réussi. |
| `cookie_name` | string | `"waf_session"` | Nom du cookie de session déposé après le challenge. |
| `pow_difficulty` | int [8–24] | `16` | Difficulté initiale du Proof-of-Work en bits. 16 bits ≈ 500ms sur un CPU standard. Augmenter augmente la charge pour le visiteur **et** pour les bots. |
| `min_elapsed_ms` | int | `0` | Temps minimum (ms) pour résoudre le challenge. `0` = **plancher désactivé** (recommandé) : sur un client rapide la PoW se résout en quelques dizaines de ms, et un plancher positif rejetait ces résolutions légitimes (`challenge_too_fast`). La résistance anti-bot vient de la PoW + fingerprint + cookie, pas du chrono. Mettre `>0` pour réactiver un plancher. |
| `max_elapsed_ms` | int | `60000` | Temps maximum (ms). Au-delà, le challenge est considéré abandonné. Marge large pour les appareils lents. |

---

## `metrics` — Endpoint Prometheus

```yaml
metrics:
  auth_token: ""   # préférer WAF_METRICS_AUTH_TOKEN
```

`/waf/metrics` est servi par le listener public, **sur tous les domaines** : derrière Cloudflare, `https://<votre-domaine>/waf/metrics` est joignable depuis Internet et un pare-feu réseau ne le restreint pas. Il révèle les domaines, les décisions, la pression et l'état du stockage.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `auth_token` | string | `""` | **Opt-in.** Token Bearer (≥ 32 caractères) exigé par `GET /waf/metrics` : sans `Authorization: Bearer <token>`, réponse `401`. Vide : endpoint public. **Utiliser `WAF_METRICS_AUTH_TOKEN`.** Recommandé en production. |

Côté Prometheus :

```yaml
scrape_configs:
  - job_name: waf
    metrics_path: /waf/metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/waf-metrics-token
```

---

## `admin` — API d'administration

```yaml
admin:
  enabled: true
  # token: "..."  # Préférer WAF_ADMIN_TOKEN
```

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active l'API d'administration sur `server.admin_listen`. |
| `token` | string | — | Token Bearer pour authentifier les appels API (≥ 32 caractères). **Utiliser `WAF_ADMIN_TOKEN`.** |

L'API expose : `GET /waf/health`, `GET /waf/stats`, et les endpoints CRUD pour la whitelist, blacklist, visiteurs, stats, events, audit, RGPD.

---

## `storage` — Stockage de l'état visiteurs

```yaml
storage:
  backend: "memory"
  # redis:
  #   address: "redis:6379"
  #   password: ""   # Préférer WAF_REDIS_PASSWORD
  #   db: 0
  #   tls: false
  #   timeout: "100ms"
```

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `backend` | string | `"memory"` | `"memory"` : état par processus, borné par `trust.max_visitors`, remis à zéro au redémarrage. `"redis"` : état **partagé entre instances** (voir ci-dessous). |
| `redis.address` | string | — | Adresse Redis au format `host:port`. **Obligatoire si `backend: "redis"`.** |
| `redis.password` | string | `""` | Mot de passe Redis. **Utiliser `WAF_REDIS_PASSWORD`.** |
| `redis.db` | int | `0` | Numéro de base Redis (0–15). |
| `redis.tls` | bool | `false` | Active TLS pour la connexion Redis. |
| `redis.timeout` | durée | `"100ms"` | Budget par opération Redis sur le chemin de requête. Un dépassement compte comme une erreur — donc rapproche la bascule en mode dégradé — plutôt que de bloquer la requête. |

**Backend `redis` — ce qu'il fait et ce qu'il ne fait pas** ([ADR-021](specs/decisions/ADR-021-redis-store-degraded-mode.md)) :

- **Clés** : `waf:visitor:<hash>` et `waf:bucket:<hash>`, valeurs JSON. L'expiration
  est déléguée à Redis (`EXPIRE` dérivé de l'échéance portée par l'état) : il n'y a
  pas de goroutine de nettoyage côté WAF.
- **Écriture traversante** : chaque écriture va dans Redis **et** dans un store
  local. Un basculement en mode dégradé hérite ainsi d'un état récent au lieu de
  repartir de zéro.
- **Mode dégradé** : après 3 erreurs Redis consécutives, le nœud sert **tout**
  depuis son état local pendant 5 s, puis re-sonde Redis. Les requêtes continuent
  d'être traitées ([FR-20](specs/requirements-advanced.md)). L'état est observable :
  jauge `waf_storage_degraded` (0/1) et compteur `waf_storage_errors_total{operation}`.
- **Redis injoignable au démarrage = erreur de démarrage.** Le WAF ne démarre pas
  silencieusement en mémoire : vous avez demandé un état partagé, une adresse ou un
  mot de passe fautif doit se voir immédiatement.
- **Éviction** : `trust.max_visitors` ne borne que le store **local**. Côté Redis,
  la borne mémoire est la `maxmemory-policy` de votre instance Redis — le WAF ne
  l'émule pas. C'est une différence de comportement réelle entre les deux backends.
- **`cluster.enabled` est indépendant du backend** : le bus d'événements Pub/Sub
  ([FR-20](specs/requirements-advanced.md)) et le store partagé sont deux mécanismes
  distincts, qui utilisent la même connexion `storage.redis`. `backend: "memory"` +
  `cluster.enabled: true` reste une combinaison valide (propagation des décisions,
  sans état partagé).
- `ListVisitors` (API admin) parcourt les clés par `SCAN` borné à
  `trust.max_visitors` entrées — jamais de `KEYS` sur un Redis de production.

---

## `whitelist` et `blacklist`

```yaml
whitelist:
  - "127.0.0.1"
  - "::1"
  - "10.0.0.0/8"

blacklist:
  - "1.2.3.4"
  - "198.51.100.0/24"
```

| Clé | Description |
|---|---|
| `whitelist` | IPs et CIDR **toujours autorisés** — bypass de toutes les protections (rate limiting, challenge, score…). À utiliser pour vos IPs internes, IPs de monitoring, etc. |
| `blacklist` | IPs et CIDR **toujours bloqués** (HTTP 403), sans aucune vérification préalable. La whitelist est prioritaire sur la blacklist. |

Les deux listes peuvent être modifiées sans redémarrage via l'API admin.

---

## `whitelist_user_agents`

```yaml
whitelist_user_agents:
  - "Googlebot"
  - "Bingbot"
  - "UptimeRobot"
```

User-agents de bots légitimes **exemptés du challenge JS proactif** (un crawler n'exécute pas le JS) **et des heuristiques anti-bot « client non navigateur »** (en-têtes `Accept-Language`/`Accept-Encoding` absents, UA d'outil type `curl/`) : un crawler n'envoie pas les en-têtes d'un navigateur. Honeypots, UA d'automation (Selenium, Puppeteer) et navigateurs headless restent pénalisés. Chaque entrée est une **expression régulière** (syntaxe RE2) recherchée dans le header `User-Agent`, **sensible à la casse** — préfixer par `(?i)` pour l'ignorer.

L'exemption consulte `risk_engine.verified_bots` : un crawler démasqué (reverse-DNS non conforme) n'en bénéficie pas, et **en mode sous attaque** (`antiddos.under_attack`) seul un crawler **vérifié** par reverse-DNS en bénéficie — un User-Agent non vérifiable (facebookexternalhit, LinkedInBot, Twitterbot…) reçoit alors le challenge.

Défaut : `Googlebot`, `Bingbot`, `Slurp`, `DuckDuckBot`, `Baiduspider`, `facebookexternalhit`, `LinkedInBot`, `Twitterbot`, `Applebot`. Chaque crawler de `risk_engine.verified_bots.crawlers` doit y figurer : un crawler vérifiable absent de cette liste est challengé sous attaque, même vérifié. Une liste explicite remplace la liste par défaut.

Ce n'est **pas** un bypass : un `User-Agent` se forge. La blacklist, l'anti-DDoS, le rate limiting et le moteur de risque s'appliquent. Un faux crawler démasqué par `risk_engine.verified_bots` (reverse-DNS) voit sa réputation dégradée et reçoit le challenge ou le blocage que décide le moteur ; un crawler vérifié est autorisé (`ALLOW`). Pour un bypass total, utiliser `whitelist` (IP ou CIDR).

---

## `honeypot_paths`

```yaml
honeypot_paths:
  - "/.env"
  - "/wp-config.php"
  - "/.git/config"
```

Chemins qui ne devraient jamais être accédés par un visiteur légitime. Toute requête vers un chemin honeypot (correspondance **exacte** du chemin) déclenche : score de confiance → 0, log d'événement de sécurité (`HONEYPOT`), blocage immédiat, puis **ban** du visiteur pendant `trust.score_ttl` : toutes ses requêtes suivantes, assets compris, reçoivent `403` (`BLOCK`, `reason=honeypot_ban`), avant tout challenge, moteur de risque actif ou non et en mode shadow.

Défaut : `/.env`, `/wp-config.php`, `/.git/config`, `/phpinfo.php`. `/admin.php`, page d'administration légitime de nombreuses applications PHP, n'en fait plus partie.

> ⚠ Ne jamais y mettre un chemin que l'application protégée **sert réellement** :
> le visiteur qui l'atteint est banni. La liste est globale — elle s'applique à
> tous les domaines. Pour un site WordPress, `/wp-admin`, `/wp-login.php` et
> `/xmlrpc.php` sont légitimes ; ils ne figurent plus dans les défauts, qui
> bannissaient l'administrateur de tout WordPress protégé.

---

## `domains` — Configuration par domaine

```yaml
domains:
  - host: "example.com"
    upstream: "http://10.0.0.1:80"
    challenge_enabled: true

  - host: "api.example.com"
    upstream: "http://10.0.0.2:8000"
    challenge_enabled: false
```

Surcharge les paramètres globaux pour un domaine spécifique. Les entrées sont évaluées dans l'ordre ; la première correspondance gagne. Supporte les wildcards (`*.example.com`).

La correspondance d'hôte est insensible à la casse et ignore le port : `Host: API.Example.com:8443` correspond à `api.example.com`. Un wildcard `*.example.com` couvre aussi l'apex `example.com`.

> **Clés retirées** ([ADR-022](specs/decisions/ADR-022-remove-inert-domain-overrides.md)) :
> `protected_paths`, `public_paths`, `rate_limit_override` et `trust_override`
> étaient acceptés puis ignorés. Ils sont désormais **refusés au démarrage**
> (`domains[N].<clé> is not supported`) : un fichier qui les contient encore doit
> en être expurgé. Pour exempter des chemins du challenge, voir
> [`static_assets`](#static_assets--bypass-des-assets-statiques) ; pour
> durcir un domaine, `challenge_enabled: true` et
> [`server.strict_host`](#server--serveur-http).

| Clé | Type | Description |
|---|---|---|
| `host` | string | Nom de domaine à matcher (exact ou wildcard `*.`). |
| `upstream` | string | URL de l'upstream pour ce domaine (surcharge `upstream.address`). |
| `challenge_enabled` | bool | Surcharge `challenge.enabled` pour ce domaine. ⚠ Sans [`server.strict_host`](#server--serveur-http), un `Host` non listé hérite de la politique **globale** et de `upstream.address` : si cet upstream est la même origine, durcir un domaine ne protège rien — il suffit de changer l'en-tête `Host` (ADR-020). Le WAF signale ce cas au démarrage (avertissement `challenge_enabled is bypassable`). **Clé absente = hérite du global** (un domaine déclaré pour son seul `upstream` ou son certificat ne perd pas le challenge). `false` = jamais de challenge JS sur ce domaine, **y compris en mode sous attaque** ([FR-39](#antiddosunder_attack--mode--sous-attaque--fr-39-adr-018)). `true` = challenge servi même si `challenge.enabled` est `false` globalement. |
| `tls.cert_file` | string | Chemin du certificat PEM (chaîne complète) présenté pour ce domaine quand `server.tls.enabled: true` (sélection par SNI). |
| `tls.key_file` | string | Chemin de la clé privée PEM correspondante. |

> Le `host` (exact ou wildcard `*.`) sert de clé de correspondance SNI. Voir
> [`server.tls`](#servertls--terminaison-tls-par-domaine-sni) pour le bloc global.

---

## `logging` — Journalisation

```yaml
logging:
  level: "info"
  format: "json"
  output: "stdout"
```

| Clé | Valeurs | Défaut | Description |
|---|---|---|---|
| `level` | `debug`, `info`, `warn`, `error` | `"info"` | Niveau de verbosité. `debug` inclut les détails de chaque décision du moteur de risque — ne pas utiliser en production sous fort trafic. |
| `format` | `json`, `pretty` | `"json"` | `json` : une ligne JSON par événement, conforme à [`security-event.schema.json`](specs/schemas/security-event.schema.json) — **contrat d'audit**, seul format exploitable par un collecteur (Loki, Datadog). `pretty` : rendu console d'une ligne par événement, lisible par un humain et colorisé sur un terminal (développement). |
| `output` | `stdout`, `stderr` | `"stdout"` | Destination des logs. Utilisez `stdout` pour Docker / Kubernetes (collecte par le runtime de conteneur). |

Les logs incluent un `request_id` unique par requête pour la corrélation.

> **`pretty` est hors du contrat d'audit.** Il promeut les champs utiles au
> diagnostic (action, IP, méthode, hôte+chemin, statut, latence, raison, score),
> en omet d'autres (`ip_hash`, `waf_latency_ms`, `cf_ray`) et masque les valeurs
> neutres. Ne l'utilisez pas là où les logs sont collectés : la conformité de
> schéma ne porte que sur `json`.
>
> La colorisation est automatiquement désactivée quand la sortie n'est pas un
> terminal (redirection, pipe, fichier) ou quand `NO_COLOR` est défini — des
> séquences ANSI dans un fichier de log le rendent illisible et cassent les greps.
> Le format ne change ni le niveau, ni la destination, ni le caractère asynchrone
> de l'écriture ([NFR-16](specs/requirements.md)).
