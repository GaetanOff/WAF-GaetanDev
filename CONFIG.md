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
| `WAF_REDIS_PASSWORD` | `storage.redis.password` | — |
| `WAF_ORIGIN_SECRET` | `origin_protection.secret` | 16 caractères |

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
```

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `listen` | string | — | Adresse d'écoute du port public (trafic entrant depuis Cloudflare). Ex : `":8080"`, `"0.0.0.0:443"`. **Obligatoire.** |
| `admin_listen` | string | `":9090"` | Adresse d'écoute de l'API d'administration. **Ne jamais exposer publiquement.** Restreignez à `127.0.0.1` ou à un réseau interne. |
| `read_timeout` | durée | `"30s"` | Délai max pour lire la requête entière (headers + body). Protège contre les connexions lentes (Slowloris). |
| `write_timeout` | durée | `"30s"` | Délai max pour envoyer la réponse complète au client. |
| `idle_timeout` | durée | `"60s"` | Délai max d'inactivité sur une connexion keep-alive avant fermeture. |
| `graceful_shutdown_timeout` | durée | `"15s"` | Délai accordé aux connexions en cours pour se terminer proprement lors d'un arrêt (SIGTERM). |

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
| `redirect_http` | bool | `true` | Rediriger le trafic HTTP (`server.listen`) vers HTTPS en `301`. |
| `cert_file` | string | `""` | Certificat PEM **par défaut**, servi pour un SNI sans correspondance. Si absent, un SNI inconnu provoque un refus de handshake. |
| `key_file` | string | `""` | Clé privée PEM du certificat par défaut. |

**Fail-fast** : un certificat manquant, illisible, ou dont la clé ne correspond
pas au certificat fait **échouer le démarrage** du WAF (on ne sert jamais un
vhost cassé). La métrique `waf_tls_cert_expiry_seconds{domain}` expose la date
d'expiration (timestamp Unix) de chaque certificat chargé.

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
| `auto_update_ranges` | bool | `false` | Récupérer automatiquement les plages IP Cloudflare depuis `https://www.cloudflare.com/ips-v4` et `ips-v6` toutes les `update_interval`. Utile si vous voulez que la liste reste à jour sans redéploiement. |
| `update_interval` | durée | `"24h"` | Fréquence de rafraîchissement des plages IP (si `auto_update_ranges: true`). |

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

Implémente un algorithme **Token Bucket** par IP. Les IPs en whitelist sont exemptées.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active/désactive le rate limiting global. |
| `requests_per_second` | float | `50` | Tokens ajoutés au bucket par seconde (débit moyen autorisé). |
| `burst` | int | `100` | Capacité maximale du bucket. Permet d'absorber un pic de trafic soudain sans déclencher immédiatement le 429. |
| `requests_per_minute` | int | `1000` | Limite cumulée sur une fenêtre glissante d'1 minute. |
| `requests_per_hour` | int | `10000` | Limite cumulée sur une fenêtre glissante d'1 heure. |

Quand la limite est atteinte : **HTTP 429** avec header `Retry-After` + pénalité de score de confiance (-10).

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
| Navigation normale | +1 par requête |
| Challenge JS échoué | -20 |
| Rate limit atteint | -10 |
| User-agent suspect | -15 |
| Pattern bot détecté | -30 |
| Honeypot déclenché | → 0 immédiat |

---

## `risk_engine` — Moteur de risque multi-signaux

```yaml
risk_engine:
  enabled: true
  profile: "balanced"
  shadow_mode: true
  block_min_confidence: 0.6
  min_corroborating_families: 2
  tiers:
    observe: 25
    throttle: 45
    challenge: 65
    tarpit: 80
    block: 90
  weights:
    reputation: 1.0
    behavioral: 1.0
    tls: 0.8
    fingerprint: 1.0
    integrity: 1.2
    rate: 0.6
    geo: 0.5
    human_credit: 1.0
  family_corroboration_threshold: 50
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

### Options principales

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active le moteur de risque. Si désactivé, seul le système de confiance `trust` est utilisé. |
| `profile` | string | `"balanced"` | Profil de sensibilité global. `lenient` : moins de faux positifs, moins de protection. `balanced` : équilibre recommandé. `strict` : plus agressif, risque accru de faux positifs. |
| `shadow_mode` | bool | `true` | **Mode calibration.** Le moteur calcule et journalise ses décisions sans les appliquer. Permet d'observer les faux positifs avant d'activer le blocage réel. **Passer à `false` après au moins 24h d'observation.** |
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
| `crawlers` | liste | `["googlebot", ...]` | Liste de sous-chaînes de user-agents à vérifier. La comparaison est insensible à la casse. |

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
| `cache_ttl` | durée | `"1h"` | Durée de mise en cache des résultats de lookup. Évite de re-interroger la même IP à chaque requête. |
| `blocklist_cidrs` | liste | `[]` | Plages CIDR considérées comme **malveillantes** → verdict `malicious` → score de risque maximum. |
| `suspect_cidrs` | liste | `[]` | Plages CIDR considérées comme **suspectes** (Tor, datacenter, VPN) → verdict `suspect` → contribution partielle au score de risque. |
| `abuseipdb.enabled` | bool | `false` | Active la consultation de l'API AbuseIPDB en complément des listes locales. |
| `abuseipdb.url` | string | URL AbuseIPDB | URL de l'endpoint AbuseIPDB. Ne pas modifier sauf si vous utilisez un proxy interne. |
| `abuseipdb.api_key` | string | `""` | Clé API AbuseIPDB. **Préférer la variable d'environnement `WAF_ABUSEIPDB_KEY`.** |

---

## `adaptive` — Difficulté PoW adaptative

```yaml
adaptive:
  enabled: true
  max_difficulty: 24
  decay_tau: "5m"
```

Ajuste dynamiquement la difficulté du challenge Proof-of-Work selon l'intensité de l'attaque. Sous attaque forte, la difficulté monte jusqu'à `max_difficulty`. Elle redescend progressivement selon `decay_tau` quand le trafic se normalise.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active l'adaptation automatique de la difficulté PoW. |
| `max_difficulty` | int [8–32] | `24` | Plafond de bits de difficulté. 24 bits ≈ 3–5 secondes sur un CPU standard. Doit être ≥ `challenge.pow_difficulty`. |
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
| `ja3_header` | string | `"Cf-Bot-Management-Ja3Hash"` | Nom du header HTTP fourni par Cloudflare contenant le hash JA3. Ne pas modifier sauf si votre proxy utilise un header différent. |
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
| `file` | string | `""` | Chemin vers le fichier YAML de règles (rechargeable à chaud sans redémarrage). **Obligatoire si `enabled: true`.** Voir `specs/schemas/rule.schema.json` pour la syntaxe. |

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

Synchronise les décisions (scores, blacklists dynamiques) entre plusieurs instances WAF via Redis Pub/Sub. Nécessite `storage.backend: "redis"`.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Active la synchronisation cluster. **Opt-in.** Requiert un Redis configuré. |
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

Protège contre les attaques qui ouvrent de nombreuses connexions HTTP lentes pour épuiser les ressources serveur.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active la protection Slowloris. |
| `max_connections_per_ip` | int | `50` | Nombre maximum de connexions simultanées acceptées par IP. Au-delà, les nouvelles connexions sont refusées immédiatement. |
| `header_timeout` | durée | `"10s"` | Délai maximum pour recevoir les headers HTTP complets. Une connexion qui n'envoie pas ses headers dans ce délai est fermée. |

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
```

Les requêtes vers des assets statiques (CSS, JS, images, fonts…) ne déclenchent pas le challenge JS. Cela évite que la page de challenge elle-même soit bloquée par le WAF.

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Active le bypass des assets statiques. |
| `extensions` | liste | Voir exemple | Extensions de fichiers bypassant le challenge. La comparaison est insensible à la casse. |

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

Remplace l'`upstream` unique par un pool load-balancé avec health checks. **Prend la priorité sur `upstream` et `domains[].upstream`** quand activé.

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
| `health_check.unhealthy_threshold` | int | `3` | Nombre de sondes échouées consécutives pour marquer un upstream comme hors service. |

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
    - type: "discord"
      url: "https://discord.com/api/webhooks/..."
```

Envoie des notifications vers Slack, Discord ou tout endpoint HTTP générique lors d'événements de sécurité critiques (pression globale critique, IP bloquée, circuit-breaker, honeypot, etc.).

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Active les alertes webhook. **Opt-in.** |
| `cooldown` | durée | `"5m"` | Délai minimum entre deux alertes identiques (même trigger + même domaine). Évite le flood de notifications. |
| `max_retries` | int | `3` | Nombre de tentatives en cas d'échec d'envoi du webhook. |
| `webhooks[].type` | string | — | Type de webhook : `"slack"`, `"discord"`, ou `"generic"` (POST JSON brut). |
| `webhooks[].url` | string | — | URL du webhook. |

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
| `enabled` | bool | `false` | Passe le WAF en **mode maintenance** : toutes les requêtes reçoivent une page 503 brandée, sauf `/waf/health` et `/waf/metrics` (sondes de monitoring). À activer lors d'une maintenance planifiée de l'upstream. |
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
  min_elapsed_ms: 500
  max_elapsed_ms: 10000
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
| `min_elapsed_ms` | int | `500` | Temps minimum (ms) pour résoudre le challenge. En dessous, la réponse est rejetée comme trop rapide (bot). |
| `max_elapsed_ms` | int | `10000` | Temps maximum (ms). Au-delà, le challenge est considéré abandonné. |

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

L'API expose : `GET /waf/health`, `GET /waf/metrics`, et les endpoints CRUD pour la whitelist, blacklist, visiteurs, stats, events, audit, RGPD.

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
```

| Clé | Type | Défaut | Description |
|---|---|---|---|
| `backend` | string | `"memory"` | `"memory"` : stockage en mémoire (simple, remise à zéro au redémarrage). `"redis"` : stockage persistant partagé entre instances (nécessaire pour `cluster.enabled: true`). |
| `redis.address` | string | — | Adresse Redis au format `host:port`. **Obligatoire si `backend: "redis"`.** |
| `redis.password` | string | `""` | Mot de passe Redis. **Utiliser `WAF_REDIS_PASSWORD`.** |
| `redis.db` | int | `0` | Numéro de base Redis (0–15). |
| `redis.tls` | bool | `false` | Active TLS pour la connexion Redis. |

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

User-agents de bots légitimes qui bypassent le challenge JS. La comparaison est une **recherche de sous-chaîne insensible à la casse** dans le header `User-Agent`.

> **Note** : Le WAF peut vérifier que ces bots sont bien ceux qu'ils prétendent être via `risk_engine.verified_bots`.

---

## `honeypot_paths`

```yaml
honeypot_paths:
  - "/.env"
  - "/wp-admin"
  - "/.git/config"
```

Chemins qui ne devraient jamais être accédés par un visiteur légitime. Toute requête vers un chemin honeypot déclenche : score de confiance → 0, log d'événement de sécurité, blocage immédiat.

---

## `domains` — Configuration par domaine

```yaml
domains:
  - host: "example.com"
    upstream: "http://10.0.0.1:80"
    challenge_enabled: true
    protected_paths:
      - "/api/"
      - "/account/"
    public_paths:
      - "/static/"
      - "/robots.txt"

  - host: "api.example.com"
    upstream: "http://10.0.0.2:8000"
    challenge_enabled: false
    rate_limit_override:
      requests_per_second: 20
      burst: 40
    trust_override:
      block_threshold: 20
```

Surcharge les paramètres globaux pour un domaine spécifique. Les entrées sont évaluées dans l'ordre ; la première correspondance gagne. Supporte les wildcards (`*.example.com`).

| Clé | Type | Description |
|---|---|---|
| `host` | string | Nom de domaine à matcher (exact ou wildcard `*.`). |
| `upstream` | string | URL de l'upstream pour ce domaine (surcharge `upstream.address`). |
| `challenge_enabled` | bool | Active ou désactive le challenge JS pour ce domaine. |
| `protected_paths` | liste | Préfixes de chemins qui déclenchent **toujours** le challenge, quelle que soit la valeur du score (utile pour `/api/`, `/admin/`). |
| `public_paths` | liste | Préfixes de chemins qui ne déclenchent **jamais** le challenge (assets, robots.txt, etc.). |
| `rate_limit_override.requests_per_second` | float | Limite de débit spécifique à ce domaine (remplace la valeur globale). |
| `rate_limit_override.burst` | int | Burst spécifique à ce domaine. |
| `trust_override.challenge_threshold` | int | Seuil de challenge JS spécifique à ce domaine. |
| `trust_override.block_threshold` | int | Seuil de blocage spécifique à ce domaine. |
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
| `format` | `json`, `pretty` | `"json"` | `json` : logs structurés (production, compatible avec Loki, Datadog, etc.). `pretty` : logs colorés lisibles par un humain (développement). |
| `output` | `stdout`, `stderr` | `"stdout"` | Destination des logs. Utilisez `stdout` pour Docker / Kubernetes (collecte par le runtime de conteneur). |

Les logs incluent un `request_id` unique par requête pour la corrélation.
