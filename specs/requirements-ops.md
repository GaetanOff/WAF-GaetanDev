---
status: implemented
version: 3.13.1
last-reviewed: 2026-10-01
extends: requirements-advanced.md (v2.0.0)
change: "FR-24 : seules les méthodes GET et HEAD sont éligibles au bypass des assets statiques (POST /x.css traverse le pipeline complet). Précédent (3.13.0) — FR-30 : /waf/metrics protégé par un token Bearer opt-in (metrics.auth_token, WAF_METRICS_AUTH_TOKEN) — 401 sans. Précédent (3.12.1) — FR-23 / NFR-11 : réalignés sur le code — header_timeout ferme la connexion sans réponse (pas de 408), slow POST borné par server.read_timeout, borne par IP sur les requêtes en cours (429 too_many_connections_per_ip) ; 408, body_min_rate, RST, exemption whitelist et métriques dédiées différés. Précédent (3.12.0) — FR-27/FR-28 : réalignés sur le code — audit.max_entries 1 000 par défaut ; anonymisation gdpr.anonymize_ip (défaut true) limitée aux journaux ; conservation = trust.score_ttl (visiteurs), 24 h (events), audit.max_entries ; rétentions configurables et rapport privacy différés. Précédent (3.11.0) — FR-21/FR-22 : réalignés sur le contrat implémenté (config.schema.json) — X-Frame-Options DENY par défaut, Permissions-Policy opt-in, HSTS quel que soit le transport ; réglages par domaine, X-XSS-Protection, X-WAF-Protected et sanitize_errors différés. Précédent (3.10.5) — FR-25 : la sonde de santé ne suit pas les redirections (3xx = succès) et applique upstream.tls_verify. Précédent (3.10.4) — FR-28 : ip_hash = HMAC-SHA256 à clé (dérivée de challenge.secret_key) au lieu d'un SHA-256 sans clé renversable sur IPv4. Précédent (3.10.3) — FR-28 : l'effacement supprime aussi buckets de rate limit, mesure THROTTLE, profil comportemental et dernier JA3. Précédent (3.10.2) — FR-23 : taille des en-têtes bornée (server.max_header_bytes, 64 Kio par défaut). Précédent (3.10.1) — FR-25 : l'annulation d'une requête par le client ne retire plus le membre du pool. Précédent (3.10.0) — FR-30 : détection de rejeu des tokens de challenge (`token_already_used`) implémentée. Précédent (3.9.5) — FR-40 : la redirection HTTPS accepte l'apex d'un domaine wildcard. Précédent (3.9.4) — FR-40 : deux serveurs démarrés sur la même adresse d'écoute sont refusés à la validation. Précédent (3.9.3) — FR-32 : la page brandée qui remplace un corps d'erreur retire les en-têtes décrivant le corps d'origine (`Content-Encoding`, `Content-Range`, `ETag`, `Last-Modified`). Précédent (3.9.2) — FR-27 : un échec d'écriture du fichier d'audit est journalisé. Précédent (3.9.1) — Terminaison TLS par domaine renumérotée FR-40 (FR-33 est le moteur de risque de requirements-detection.md). Précédent (3.9.0) — FR-24 : bypass par préfixe de répertoire et par chemin exact (`path_prefixes`, `exact_paths`) et métrique `waf_asset_requests_total{domain}` implémentés. Précédent (3.8.3) — FR-25 : adresses du pool validées au démarrage (URL absolue). Précédent (3.8.2) — FR-30 : corps JSON client borné avant décodage (16 Kio /waf/verify, 64 Kio API admin). Précédent (3.8.1) — FR-31 : contrat réel du bloc `acme` (pas de `server.tls.acme`), exclusif de `server.tls` ; jauge d'expiration ACME différée. Précédent (3.8.0) — FR-30 : /waf/verify, API admin et /waf/metrics réalignés sur le contrat implémenté (verify_max_per_minute, admin_max_failures/admin_lockout) ; rejeu, max_pending_nonces, amplification, blacklists automatiques et metrics.auth_token différés. Précédent (3.7.0) — FR-24 : le bypass des assets statiques n'exempte plus du rate limit (aligné sur static-assets-bypass.feature). Précédent (3.6.0) — FR-26 : avertissement au démarrage pour tout domains[].upstream rendu inerte par le pool. Précédent (3.5.1) — FR-32 : un 4xx n'est brandé que si son corps est en texte brut (ou sans type) — une erreur JSON d'API reste intacte même pour une navigation. Précédent (3.5.0) — FR-25/FR-26 : réalignés sur le pool implémenté (upstream-pool.schema.json v2.0.0, seuils healthy/unhealthy_threshold), retry et observabilité des upstreams différés ; FR-29 : triggers émis et `id`. FR-30 : ADR-019 accepté (option B) — tout `CF-*` d'une connexion non prouvée Cloudflare est supprimé à l'entrée ; ADR-020 accepté (1C + 2A) — `server.strict_host` (opt-in) refuse un `Host` non déclaré"
---

# Requirements Ops — WAF Anti-DDoS / Anti-Bot (v3)

> Ce document comble les gaps opérationnels et de conformité identifiés à l'audit.
> IDs FR-21 à FR-32 et FR-40 font suite aux FR-01 à FR-20 (FR-33 à FR-39 : requirements-detection.md).

---

## FR-21 — Security Headers Injection

- Contrat de configuration : bloc `security_headers` de `config.schema.json`
  (global, pour tous les domaines)
- Le WAF DOIT injecter des security headers dans **toutes** les réponses transmises au client
- Headers injectés par défaut (configurables et désactivables) :
  | Header | Valeur par défaut | Clé | Description |
  |--------|------------------|-----|-------------|
  | `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | `hsts_max_age`, `hsts_include_subdomains` | Force HTTPS (`hsts_max_age: 0` le désactive) |
  | `X-Frame-Options` | `DENY` | `frame_options` | Clickjacking protection (`SAMEORIGIN` autorise l'iframe même origine, `""` désactive) |
  | `X-Content-Type-Options` | `nosniff` | `content_type_nosniff` | MIME-type sniffing protection |
  | `Referrer-Policy` | `strict-origin-when-cross-origin` | `referrer_policy` | Contrôle des données de référent |
- `Permissions-Policy` (`permissions_policy`) et `Content-Security-Policy` (`csp`)
  sont **opt-in** : vides par défaut, header non injecté. Une CSP générique
  casserait les sites protégés
- `X-Frame-Options` vaut `DENY` par défaut : le code, `config.schema.json` et
  CONFIG.md l'ont toujours appliqué ; cette exigence annonçait `SAMEORIGIN`
  (ADR-011). `DENY` est le choix le plus strict, un domaine qui s'affiche dans
  une iframe même origine configure `SAMEORIGIN`
- HSTS est injecté quel que soit le transport de la connexion au WAF : derrière
  Cloudflare, le WAF reçoit du HTTP alors que le client est en HTTPS. Un
  navigateur ignore HSTS reçu en HTTP clair (RFC 6797 §8.1)
- Si l'upstream envoie déjà un header, le WAF NE DOIT PAS l'écraser (upstream a la priorité)
- **Différé** (spécifié, non implémenté — `security-headers.feature`, scénarios
  `@deferred`) : réglages par domaine (CSP, désactivation), `X-XSS-Protection`,
  signature `X-WAF-Protected`

## FR-22 — Response Sanitization (Masquage d'informations)

- Le WAF DOIT **supprimer** les headers de réponse qui révèlent l'infrastructure
  upstream, listés par `security_headers.strip_headers` (défaut : `Server`,
  `X-Powered-By`). L'opérateur y ajoute `X-Generator`, `X-AspNet-Version`,
  `X-AspNetMvc-Version`, `Via`… selon sa stack
- La sanitisation s'applique avant l'injection de FR-21 : un header retiré puis
  géré par FR-21 reçoit la valeur du WAF
- Les corps d'erreur 4xx/5xx de l'upstream sont remplacés par une page brandée
  sans détail technique avec `maintenance.error_pages` (FR-32)
- **Différé** (`@deferred`) : valeur de remplacement configurable du header
  `Server`, bloc `sanitize_errors` (remplacement ciblé des seuls corps 5xx
  contenant une stack trace ou un chemin de fichier)

## FR-23 — Protection Slowloris & Slow HTTP

- Contrat de configuration : bloc `slowloris` et clés `server.read_timeout`,
  `server.idle_timeout`, `server.max_header_bytes`, `server.max_header_value_count`
  de `config.schema.json`
- Le WAF DOIT borner la réception des en-têtes HTTP (**Slowloris**) :
  - `slowloris.header_timeout` (défaut `10s`), délai de lecture de l'ensemble des
    en-têtes (pas de chaque ligne) — `http.Server.ReadHeaderTimeout`
  - Délai dépassé → le serveur HTTP ferme la connexion **sans réponse** : aucun
    middleware ne s'est exécuté, rien n'est journalisé
  - Le délai de `10s` s'applique aussi quand `slowloris.enabled` est faux
- Le WAF DOIT borner la lecture du corps (**Slow POST**) par `server.read_timeout`
  (défaut `30s`) : durée totale de lecture de la requête, en-têtes et corps
  compris. Au-delà, la lecture du corps échoue et la connexion est fermée
- Le WAF DOIT fermer une connexion keep-alive inactive au-delà de
  `server.idle_timeout` (défaut `60s`)
- Le WAF DOIT borner le nombre de **requêtes en cours** par IP client :
  - `slowloris.max_connections_per_ip` (défaut: 50), compté par IP réelle (FR-02,
    une IPv6 par son /64) : derrière Cloudflare, les connexions TCP viennent des
    points de présence, seule une borne par requête suit le visiteur
  - Au-delà → `429` avec `Retry-After: 10`, `X-WAF-Action: RATE_LIMIT`,
    `X-WAF-Reason: too_many_connections_per_ip`, journalisé et compté dans
    `waf_requests_total` (FR-09)
  - Appliquée dans l'enveloppe, à tout chemin sauf `/waf/health`, avant la
    whitelist : une IP whitelistée y est soumise
- **Différé** (`slowloris-protection.feature`, scénarios `@deferred`) : réponse
  `408` et event `slowloris_headers_timeout` à l'expiration des en-têtes, débit
  minimal du corps (`body_min_rate`, event `slow_body_rate`), rejet par TCP RST,
  exemption de la whitelist, métriques dédiées (`waf_slowloris_blocked_total`,
  `waf_slow_post_blocked_total`, `waf_connections_per_ip_max`,
  `waf_active_connections`)
- Le WAF DOIT borner la **taille des en-têtes** d'une requête, sur le listener public,
  l'API admin et les serveurs annexes :
  - `max_header_bytes`: configurable (défaut: 65536 ; `0` = défaut Go, 1 Mio)
  - Au-delà → `431 Request Header Fields Too Large`, avant tout middleware. Sans borne,
    chaque requête pouvait faire parser 1 Mio d'en-têtes
- Le WAF DOIT borner le **nombre de valeurs d'en-tête** acceptées par requête :
  - `max_header_value_count`: configurable (défaut: 100 ; `0` = défaut Go, 500)
  - Au-delà → la requête est rejetée par le serveur HTTP avant d'atteindre les middlewares
  - Complète `max_connections_per_ip` : borne le coût d'**une seule** requête portant des
    milliers de lignes d'en-tête (amplification mémoire/CPU au parsing), là où la limite de
    connexions borne le nombre de requêtes concurrentes
  - Les valeurs séparées par des virgules sur une même ligne comptent pour 1 ; les lignes
    d'en-tête répétées comptent chacune
- Ces protections DOIVENT fonctionner avant la lecture complète de la requête (niveau net.Conn / http.Server)

## FR-24 — Bypass des Assets Statiques

- Le WAF DOIT bypasser le challenge, le trust score et les détecteurs de signal pour les **assets statiques connus** :
  - Par extension : `.css`, `.js`, `.map`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.svg`, `.ico`, `.woff`, `.woff2`, `.ttf`, `.eot`
  - Par path prefix configurable (`static_assets.path_prefixes`, défaut : `/static/`, `/assets/`, `/public/`, `/dist/`) — préfixe de répertoire, commençant et finissant par `/`, `/` seul refusé
  - Par path exact configurable (`static_assets.exact_paths`, défaut : `/favicon.ico`, `/robots.txt`, `/sitemap.xml`)
  - L'extension est comparée sans tenir compte de la casse ; préfixes et chemins exacts le sont à la casse près (un chemin d'URL y est sensible)
- Le WAF DOIT tout de même vérifier la whitelist/blacklist pour les assets (les IPs blacklistées ne peuvent pas accéder aux assets)
- Seules les méthodes `GET` et `HEAD` sont éligibles au bypass : un `POST`, `PUT`,
  `PATCH` ou `DELETE` vers un chemin d'asset (`POST /login.css`,
  `PUT /static/shell.php`) traverse le pipeline complet. Motif : le PASS
  court-circuite intégrité, règles, géo, threat intel, anti-bot et anti-DDoS ;
  sans borne de méthode, toute écriture vers une URL finissant par `.css`
  échappait à ces contrôles
- Le bypass NE DOIT PAS exempter du **rate limit** : les requêtes d'assets sont
  comptées dans les buckets de l'IP et reçoivent `429` au-delà (le PASS porte
  la raison `static_asset`, que le rate limit distingue du PASS de la whitelist IP)
  - Motif : sans cette borne, toute URL finissant par une extension d'asset
    (`/x.css`) inondait l'origine sans limite. La contradiction avec
    `static-assets-bypass.feature` (« Bypass n'inclut pas le rate limit ») est
    tranchée en faveur du scénario (sécurité > perf)
- Le WAF NE DOIT PAS servir de page de challenge pour une requête d'asset statique
- Le WAF DOIT compter les requêtes d'assets dans les métriques (`waf_asset_requests_total{domain}`, label `domain` borné comme celui de `waf_requests_total`)
- La liste des extensions d'assets DOIT être configurable et extensible
- En cas de doute (path ambigu), le WAF DOIT traiter comme non-asset (sécurité > perf)

## FR-25 — Upstream Health Checks & Failover

- Contrat de configuration : bloc `upstream_pool` (`schemas/upstream-pool.schema.json`
  v2.0.0, identique à `config.schema.json`)
- Le WAF DOIT effectuer des **health checks actifs** sur chaque upstream configuré :
  - Méthode : HTTP GET sur `health_check.path` (défaut: `/healthz`) ; 2xx ou 3xx = succès.
    Une redirection n'est PAS suivie : le 3xx de la sonde est lui-même le succès
    (suivre `Location` jugeait la santé d'une autre URL, voire d'un autre hôte)
  - La sonde applique `upstream.tls_verify`, comme le proxy : avec `false`, une
    origine HTTPS à certificat auto-signé échouait toutes ses sondes et le pool
    entier sortait du service alors que le proxy la joignait
  - Intervalle configurable (`interval`, défaut: `10s`)
  - Timeout du health check : configurable (`timeout`, défaut: `2s`)
  - Succès consécutifs pour remettre un upstream en service (`healthy_threshold`, défaut: 2)
  - Échecs consécutifs pour le retirer du service (`unhealthy_threshold`, défaut: 3)
- Chaque `upstream_pool.upstreams[].address` DOIT être une URL absolue (schéma
  et hôte), comme `upstream.address` : une adresse invalide est refusée au
  démarrage, et non découverte par les sondes
- Une erreur de proxy sur une requête DOIT retirer le membre du service
  immédiatement (le client reçoit `502`) ; les sondes le remettent en service.
  Le départ du client (requête annulée, `context.Canceled`) n'est PAS une erreur
  de l'upstream et NE DOIT PAS retirer le membre : une seule annulation mettait
  un pool d'un membre hors service pour tous les visiteurs
- Quand un upstream est retiré du service :
  - Si un **upstream de secours** (`backup`) est configuré et qu'aucun principal
    n'est sain, basculer automatiquement
  - Si aucun membre n'est sain : `502 no healthy upstream`
- **Différé** (spécifié, non implémenté — `upstream-health.feature`, scénarios
  `@deferred`) : page de maintenance `503` quand tout est hors service (FR-32) ;
  log events `UPSTREAM_DOWN`/`UPSTREAM_UP`, métrique `waf_upstream_health` et
  webhooks associés ; `GET /waf/admin/upstreams` ; sonde HEAD, statut ou corps
  attendus ; **retry** d'une requête idempotente sur un autre membre

## FR-26 — Load Balancing Multi-Upstream

- Le WAF DOIT supporter un **pool d'upstreams** global (prioritaire sur
  `upstream.address` et `domains[].upstream`) avec plusieurs stratégies :
  - `round_robin` : rotation à tour de rôle (défaut)
  - `least_conn` : upstream avec le moins de requêtes en cours
  - `ip_hash` : même IP réelle toujours routée vers le même upstream sain
  - `weighted` : répartition selon le **poids** (`weight: N`, défaut 1), lu par
    cette seule stratégie
- Le WAF DOIT exclure automatiquement les upstreams hors service (intégré avec FR-25)
- Pool actif, un `domains[].upstream` distinct de `upstream.address` ne reçoit
  aucune requête : le WAF DOIT l'avertir au démarrage (un avertissement par hôte)
  plutôt que de laisser croire à un routage par domaine
- **Différé** : stratégie `random`, pool par domaine, page de maintenance quand
  tout est hors service, métriques `waf_upstream_requests_total{upstream}` et
  `waf_upstream_response_time_seconds{upstream}`

## FR-27 — Audit Trail des Actions Admin

- Le WAF DOIT maintenir un **journal d'audit immuable** de toutes les actions sur l'API admin :
  - Champs : `timestamp`, `action`, `endpoint`, `method`, `request_body` (secrets masqués), `response_status`, `client_ip`
  - Exemples : ajout en blacklist, modification config, reset visiteur, activation/désactivation règle
- Le journal DOIT être accessible via `GET /waf/admin/audit` (pagination
  `page`/`limit`, de la plus ancienne à la plus récente entrée)
- **Différé** : filtres `since`, `until` et `action` (`audit-trail.feature`,
  scénarios `@deferred`)
- Le journal DOIT être **append-only** en mémoire (pas de suppression via API)
- La taille max du journal en mémoire DOIT être configurable (`audit.max_entries`, défaut : 1 000 entrées, rotation FIFO — `config.schema.json`)
- En option, le journal DOIT pouvoir être écrit sur disque (fichier JSON-lines configurable)
  - Un échec d'écriture du fichier (disque plein, fichier révoqué) NE DOIT PAS
    faire échouer l'action admin, mais DOIT être journalisé en erreur ;
    l'entrée reste consultable en mémoire
- Toute action admin NE DOIT PAS être effectuée sans être journalisée (atomicité log + action)

## FR-28 — Conformité GDPR & Privacy

- Le WAF DOIT supporter un mode **IP anonymisation** (`gdpr.anonymize_ip`, défaut `true`) :
  - IPv4 : masquer le dernier octet (`192.168.1.0`, /24)
  - IPv6 : masquer les 80 derniers bits (/48)
  - Quand actif, les journaux de sécurité (`SecurityEvent`, flux `GET /waf/admin/events`)
    portent l'IP anonymisée. Le scoring, le store et les listes d'accès utilisent
    l'IP réelle : leur clé est l'`ip_hash` (ci-dessous), jamais l'IP en clair, et
    une blacklist sur l'IP exacte reste appliquée
- Le WAF DOIT borner la **conservation des données** :
  - `VisitorState` : `trust.score_ttl` (défaut 1 h) après la dernière requête ;
    purge automatique par le store (goroutine toutes les 60 s en mémoire, TTL
    des clés avec Redis)
  - Security events du flux admin : les 10 000 dernières décisions de mitigation
    en mémoire, jamais servies au-delà de 24 h
  - Audit trail : `audit.max_entries` entrées en mémoire (FIFO) ; la rotation du
    fichier `audit.file` relève de l'opérateur
- **Différé** (`gdpr-compliance.feature`, scénarios `@deferred`) : durées de
  rétention configurables (`privacy.data_retention_hours`,
  `privacy.event_retention_hours`) et purge par âge des events déjà en mémoire ;
  rapport `GET /waf/admin/privacy/report`
- Le WAF DOIT fournir un endpoint `DELETE /waf/admin/visitors/{ip_hash}` pour le **droit à l'effacement** (déjà dans FR-10 mais formalisé ici avec audit log)
- L'effacement (`DELETE /waf/admin/visitors/{ip_hash}` comme `POST /waf/admin/gdpr/erase`) DOIT supprimer **tout** l'état tenu pour le visiteur : `VisitorState`, buckets de rate limit des trois fenêtres (store partagé compris) et mesure `THROTTLE`, profil comportemental (chemins visités), dernier JA3 retenu. Il ne supprimait que le `VisitorState`, alors que le registre des traitements annonce la suppression de toutes les données
- Le WAF NE DOIT PAS logger les query parameters en clair dans les logs `info` et `warn` (déjà couvert en FR-09 mais formalisé)
- Le WAF DOIT documenter dans le README quelles données personnelles sont traitées et pour quelle durée (registre de traitement)
- En mode anonymisation, les fingerprints sont toujours hashés (comportement inchangé — privacy by design)
- L'`ip_hash` (clé du store, des cookies et tokens de challenge, champ des journaux) DOIT être un **HMAC-SHA256 à clé** du client (FR-02), tronqué à 16 caractères hex — jamais un SHA-256 sans clé : celui d'une IPv4 se renversait en parcourant les 2³² adresses, et l'`ip_hash` n'était pas la pseudonymisation annoncée par le registre des traitements. La clé DOIT dériver de `challenge.secret_key` (HMAC du secret et de l'étiquette `waf/ip-hash/v1`), pour être la même sur les instances qui partagent un store et survivre aux redémarrages ; sans secret, une clé aléatoire par processus s'applique (avertissement au démarrage avec le backend Redis). Changer de secret rend inaccessibles les états indexés par l'ancienne clé

## FR-29 — Alerting & Webhooks

- Le WAF DOIT supporter l'envoi de **webhooks** sur des événements de sécurité configurables :
  - Format : HTTP POST vers une URL configurée, body JSON (voir `schemas/alert.schema.json`)
  - Retry : `alerting.max_retries` nouvelles tentatives (défaut 3) avec backoff exponentiel (1s, 5s, 25s, plafonné à 25s au-delà)
  - Timeout par appel : 5s
- **Triggers émis** (enum `trigger` de `schemas/alert.schema.json`) :
  | Trigger | Description |
  |---------|-------------|
  | `block` | Requête bloquée par une décision WAF (sévérité warning) |
  | `circuit_breaker` | Circuit-breaker ouvert pour une IP |
  | `honeypot` | Visite d'un chemin honeypot |
  | `under_attack_start` / `under_attack_end` | Entrée / sortie du mode sous attaque (FR-39), hors cooldown |
- Chaque alerte porte un `id` UUID v4 unique, qui permet au destinataire de
  dédoublonner une alerte relivrée par le retry
- **Triggers différés** — spécifiés, sans émetteur à ce jour : `ddos_detected`,
  `upstream_down`, `upstream_recovered`, `score_flood`, `challenge_flood`,
  `rule_triggered`, `tls_cert_expiring`. Ils rejoindront l'enum du schéma avec
  leur émetteur
- **Intégrations prêtes à l'emploi** :
  - Slack (format Slack Incoming Webhook)
  - Discord (format Discord Webhook)
  - Generic HTTP (JSON libre, configurable)
- Le WAF DOIT exposer les métriques d'alertes, comptées par livraison (une alerte × un sink) :
  - `waf_alerts_sent_total{trigger}` : livraisons acceptées par le sink (réponse 2xx)
  - `waf_alerts_failed_total{trigger}` : livraisons abandonnées (tentatives épuisées)
  - `waf_alerts_pending` : jauge des alertes en attente d'envoi. Une jauge ne porte pas le suffixe `_total`, réservé aux compteurs Prometheus (la v1 de cette spec la nommait `waf_alerts_pending_total`)
- Les webhooks NE DOIVENT PAS bloquer le pipeline de traitement des requêtes (exécution asynchrone via channel)
- Un webhook défaillant NE DOIT PAS retarder la livraison aux autres : chaque sink a sa file (256 alertes) et son worker. Avec un worker unique, un webhook hors service immobilisait l'envoi (max_retries+1 timeouts de 5 s plus les backoffs par alerte), la file se remplissait et les alertes suivantes étaient jetées sans trace
- Après une livraison abandonnée, un sink ne reçoit plus qu'**une** tentative par alerte jusqu'à son prochain succès, qui rétablit les retries : un webhook hors service coûte un timeout par alerte
- Une alerte jetée parce que la file de son sink est pleine DOIT être comptée dans `waf_alerts_failed_total`
- L'arrêt du WAF interrompt le backoff et la requête en cours ; les alertes encore en file sont abandonnées

## FR-30 — Auto-protection du WAF

### Assainissement des en-têtes internes à l'ingress

- Les middlewares du WAF se coordonnent en posant des en-têtes `X-WAF-*` **sur la
  requête**, relus par les middlewares en aval : `X-WAF-Action`, `X-WAF-Reason`,
  `X-WAF-Score`, `X-WAF-Score-Delta`, `X-WAF-Risk-*`, `X-WAF-Global-Pressure`,
  `X-WAF-Under-Attack`, `X-WAF-Under-Attack-Enforce`, `X-WAF-Origin-Token`, etc.
  Ces en-têtes sont de l'**état interne de confiance** : ils DOIVENT provenir du
  pipeline, jamais du client
- Le WAF DOIT supprimer de la requête entrante **tout en-tête dont le nom commence
  par `X-WAF-`**, avant l'exécution de tout middleware qui lit ces en-têtes. Seule
  la capture décrite plus bas peut s'exécuter en amont, et elle ne fait que
  mémoriser une valeur sans l'interpréter
  - La suppression est faite **par préfixe**, et non par liste nominative : tout
    en-tête interne ajouté ultérieurement est couvert d'office. Une liste
    nominative se désynchronise en silence, et son oubli est un fail-open
  - L'appariement DOIT être insensible à la casse (`x-waf-action`,
    `X-WAF-ACTION`, `X-Waf-Action` sont le même en-tête)
- Aucun autre en-tête NE DOIT être altéré — en particulier `CF-Connecting-IP`
  (FR-02), les `X-Forwarded-*` et `Authorization`, dont dépendent l'extraction
  d'IP réelle et l'API admin (FR-10)
- Les en-têtes internes posés **à l'intérieur** du pipeline NE DOIVENT PAS être
  affectés : `X-WAF-Action: PASS` de la whitelist (FR-04) et du bypass d'assets
  statiques (FR-24), les `X-WAF-Risk-*` des détecteurs de familles de risque
  (FR-11, FR-12, FR-16, FR-18), `X-WAF-Origin-Token` (FR-19). L'assainissement
  s'applique une seule fois, à l'entrée
- **Exception unique et documentée** : `GET /waf/origin/verify` (FR-19) est un
  oracle de vérification appelé **par l'upstream**, qui lui retransmet le
  `X-WAF-Origin-Token` qu'il a reçu. Cette valeur DOIT rester accessible à cet
  endpoint malgré l'assainissement — sans quoi l'endpoint répond `401` à tout
  token, y compris valide. L'exception n'ouvre aucun contournement : la valeur
  est vérifiée par HMAC, la forger exige le secret
  - La valeur DOIT être capturée **avant** l'assainissement et transmise à
    l'endpoint hors de `r.Header` (contexte de requête). Une exemption par
    **chemin** à l'intérieur de l'assainisseur est interdite : sa correction
    dépendrait d'une normalisation de chemin identique à celle du routeur, un
    vecteur de contournement classique
  - Aucun autre en-tête `X-WAF-*` NE DOIT être capturé de cette façon, et aucun
    en-tête capturé NE DOIT être réinjecté dans `r.Header`
- Motif : `X-WAF-Action: PASS` est testé en court-circuit par le challenge
  (FR-06), le rate limiting (FR-03), l'analyse d'intégrité (FR-18), le threat
  intel (FR-13) et le moteur de règles (FR-17). Sans assainissement, un client
  qui pose lui-même cet en-tête obtient un **contournement complet du WAF en un
  seul en-tête**. La menace est atteignable depuis Internet : les proxies amont,
  Cloudflare compris, ne filtrent pas les en-têtes `X-*` arbitraires

- **Principe général** : aucune décision de sécurité NE DOIT reposer sur un
  en-tête de requête dont le WAF ne peut pas prouver l'origine. Les en-têtes
  internes (`X-WAF-*`) sont couverts par la règle ci-dessus ; les en-têtes
  **d'infrastructure** posés par un intermédiaire relèvent d'ADR-019 (`accepted`,
  option B) et l'en-tête `Host` d'ADR-020 (`accepted`, options 1C et 2A) :
  - Le WAF DOIT supprimer tout en-tête `CF-*` (préfixe insensible à la casse)
    d'une connexion qui ne vient pas d'une plage Cloudflare, et de toute
    connexion quand `cloudflare.trusted` est faux. Un `CF-Connecting-IP` forgé
    reste rejeté en `400` (FR-02). La suppression précède tout lecteur de `CF-*`
    et le proxy
  - Cette suppression aligne la forge sur l'omission, sans fermer l'omission :
    FR-16 (géo) et la blacklist JA3 de FR-11 restent des contrôles de réduction
    de bruit tant que le WAF est joignable hors Cloudflare, et DOIVENT être
    documentés comme tels. Un `ja3_header` hors espace `CF-` n'est pas couvert
  - Avec `server.strict_host: true`, une requête dont le `Host` ne correspond à
    aucune entrée `domains[]` DOIT recevoir un `400`
    (`X-WAF-Reason: host_not_declared`), `/waf/health` excepté. Défaut `false` ;
    tant qu'il l'est, le durcissement par domaine de FR-06 est contournable par
    un `Host` non listé qui atteint la même origine, et DOIT être documenté
    comme tel
  - Aucune liaison SNI ↔ `Host` n'est exigée

### Protection de l'endpoint /waf/verify
- Le WAF DOIT borner `POST /waf/verify` par IP réelle :
  `self_protection.verify_max_per_minute` (défaut: 60, fenêtre fixe d'une minute).
  Au-delà : `429` avec `Retry-After`, `X-WAF-Action: RATE_LIMIT`,
  `X-WAF-Reason: self_protect_flood`
- Le corps DOIT être validé contre `challenge-submission.schema.json` avant tout
  traitement : un corps invalide (JSON malformé, champ manquant, `nonce` non
  numérique) reçoit `400 {"error": "invalid_submission"}`
- Un token de challenge NE DOIT être accepté qu'une fois : une soumission qui
  réutilise un token déjà accepté reçoit `400 {"error": "token_already_used"}`
  (`X-WAF-Action: BLOCK`, `X-WAF-Reason: verify_token_already_used`), sans
  cookie ni bonus de score. Sans cela, une seule PoW résolue se rejouait
  jusqu'à expiration du token, chaque soumission réappliquant le bonus
  - Seule une soumission acceptée consomme le token ; la vérification et la
    consommation sont atomiques (deux soumissions concurrentes : une seule passe)
  - Le rejeu n'est pas pénalisé (double envoi légitime d'un navigateur)
  - La mémoire des tokens consommés est locale à l'instance, bornée
    (65 536 entrées) et purgée à l'expiration des tokens. Saturée, elle laisse
    passer sans retenir plutôt que de refuser les visiteurs légitimes ; le
    rejeu reste alors lié à l'IP et au domaine signés dans le token
- **Différé** (`waf-self-protection.feature`, scénarios `@deferred`) :
  blacklist automatique d'1 h d'une IP qui dépasse la borne ; blacklist sur
  échecs de tokens répétés ; mémoire des tokens consommés partagée entre
  instances

### Protection de l'API Admin
- L'API admin DOIT verrouiller une IP après `self_protection.admin_max_failures`
  échecs d'authentification (défaut: 5) : `429 {"error": "locked"}` pendant la
  fenêtre `self_protection.admin_lockout` (défaut: `5m`), token valide compris.
  Seuls les échecs sont comptés
- Le token Bearer DOIT être comparé en temps constant, longueur comprise
- **Différé** : blacklist 24 h sur le port admin, event d'audit
  `ADMIN_AUTH_FLOOD` et webhook associé, `admin.allowed_ips`

### Protection de l'endpoint /waf/metrics
- `/waf/metrics` est servi par le listener public, sur tous les domaines :
  derrière Cloudflare, un firewall réseau ne le restreint pas. Il expose les
  domaines, les décisions, la pression et l'état du stockage
- Avec `metrics.auth_token` (opt-in, ≥ 32 caractères, `WAF_METRICS_AUTH_TOKEN`),
  `GET /waf/metrics` DOIT exiger `Authorization: Bearer <token>` : sinon `401`
  avec `WWW-Authenticate: Bearer`. La comparaison DOIT être en temps constant,
  longueur comprise. Sans token configuré, l'endpoint reste public
- Les refus d'enveloppe (`strict_host`, slowloris) et le `405` précèdent la
  vérification du token

### Parsing JSON des entrées non fiables
- Tout corps JSON provenant d'un client (`POST /waf/verify`, API admin) DOIT être
  rejeté (HTTP 400) s'il contient un **nom de membre dupliqué**
  - Motif : un parseur « le dernier gagne » côté WAF et « le premier gagne » côté
    origine créent un **différentiel de parseur** — le WAF inspecte une valeur que
    l'origine ne traitera pas. Le WAF NE DOIT PAS arbitrer un corps ambigu
- Tout corps JSON client DOIT être rejeté s'il contient de l'**UTF-8 invalide**
  - Motif : le remplacement silencieux par U+FFFD fait diverger la valeur inspectée
    de la valeur reçue sur le fil
- Le WAF DOIT continuer d'appairer les noms de membre **sans tenir compte de la
  casse** : ce durcissement ne doit pas casser les clients existants
- Tout corps JSON client DOIT être lu sous une borne de taille, avant tout
  décodage : 16 Kio pour `POST /waf/verify`, 64 Kio pour l'API admin. Au-delà,
  la requête reçoit le `400` de l'opération (`invalid_submission` pour
  `/waf/verify`)
  - Motif : `/waf/verify` est servi en amont de l'analyse d'intégrité (FR-18),
    seule à borner le corps ; un flux de plusieurs centaines de Mo était décodé
    en mémoire
- Les charges utiles dont l'authenticité est déjà établie par HMAC (cookie de
  session, nonce) et les réponses d'API tierces sont **hors périmètre** : les
  premières sont produites par le WAF lui-même, les secondes doivent tolérer
  l'ajout de champs par le fournisseur

### Protection globale du WAF
- **Différé** : détection des **amplification attacks** sur le challenge (un
  visiteur qui génère plus de N tokens sans jamais les soumettre voit ses nonces
  supprimés et est challengé plus sévèrement) et limite
  `challenge.max_pending_nonces` par IP. Les deux supposent un store de nonces,
  qui n'existe pas : le token de challenge est sans état

## FR-31 — TLS Termination & ACME/Let's Encrypt

- Quand le WAF est configuré pour terminer TLS — bloc `acme` (Let's Encrypt) ou
  `server.tls` (certificats statiques par SNI, FR-40), mutuellement exclusifs sur
  un même listener ; il n'existe pas de sous-bloc `server.tls.acme` :
  - Le WAF DOIT supporter des certificats statiques (cert + key file) configurable
  - Le WAF DOIT supporter **ACME/Let's Encrypt** avec renouvellement automatique (≥ 30 jours avant expiration)
  - Le défi ACME `HTTP-01` DOIT être géré automatiquement (bypass du challenge WAF pour les paths `/.well-known/acme-challenge/`)
  - Le défi ACME `TLS-ALPN-01` DOIT être optionnellement supporté
  - Les certificats DOIVENT être stockés sur disque (path configurable) ; les
    certificats ACME renouvelés sont pris en compte sans redémarrage
    (autocert). **Différé** : rechargement des certificats statiques sans
    redémarrage (`SIGHUP`, cf. FR-40)
  - Une métrique `waf_tls_cert_expiry_seconds{domain}` DOIT être exposée pour
    les certificats statiques. **Différé** : la même jauge pour les
    certificats ACME
- Le WAF DOIT supporter **TLS 1.2 et 1.3** côté client, configurable
  (`server.tls.min_version` ; plancher fixe TLS 1.2 en mode ACME)
- Le WAF DOIT supporter la configuration des cipher suites (liste configurable
  avec défaut sécurisé, `server.tls.cipher_suites`, certificats statiques)
- **Différé** : certificat expirant dans < 7 jours → alert webhook (FR-29) ;
  aujourd'hui seule la jauge `waf_tls_cert_expiry_seconds{domain}` (timestamp
  NotAfter des certificats statiques, publiée au démarrage) est exposée

## FR-32 — Page de Maintenance & Erreurs Custom

- Le WAF DOIT servir une **page de maintenance custom** quand l'upstream est indisponible :
  - Template HTML configurable par domaine (`maintenance_page: /path/to/maintenance.html`)
  - Si non configuré, une page de maintenance par défaut est utilisée (branding GaetanDev.fr)
  - HTTP 503 avec header `Retry-After` configurable
- Le WAF DOIT supporter des **pages d'erreur custom** pour chaque code HTTP :
  - 403 (bloqué) : page personnalisable avec message optionnel
  - 429 (rate limit) : page avec timer de countdown
  - 503 (maintenance) : page avec message et contact optionnel
- Les pages d'erreur custom DOIVENT être des templates Go (`html/template`) avec variables injectables :
  - `{{.StatusCode}}`, `{{.Domain}}`, `{{.RetryAfter}}`, `{{.RequestID}}`
- Le WAF DOIT supporter le mode `maintenance_forced: true` : forcer la page de maintenance pour tout le trafic (outil de déploiement)
- Les **pages d'erreur brandées** (remplacement du corps 4xx/5xx) ne DOIVENT s'appliquer qu'aux **navigations de navigateur** (`Accept: text/html`). Les appels API/XHR (`Accept: application/json`, `*/*`, ou absent) DOIVENT conserver leur corps d'erreur d'origine (souvent JSON), sinon les clients `fetch`/`axios` ne peuvent plus parser la réponse. La page de maintenance forcée (503) reste servie à tous
- Pour les erreurs **5xx** (502/503/504 : origine/passerelle en panne), le WAF DOIT remplacer le corps **même s'il est déjà en HTML** : une page d'erreur générique d'un reverse proxy en aval (nginx/OpenResty) n'est pas du contenu applicatif à préserver. Pour les **4xx**, le WAF NE DOIT remplacer que les corps en **texte brut** (`text/plain`) ou **sans `Content-Type`** — la forme des refus du WAF —, afin de préserver les pages d'erreur HTML et le JSON légitimes des applications. Le critère « non-HTML » remplaçait une erreur JSON d'API (400, 422) dès que la requête acceptait `text/html`
- Quand le WAF remplace un corps d'erreur, il DOIT retirer les en-têtes qui décrivaient le corps d'origine : `Content-Encoding`, `Content-Range`, `ETag`, `Last-Modified`. La page brandée est servie en clair ; un `Content-Encoding: gzip` recopié de l'upstream faisait échouer son décodage par le navigateur (`ERR_CONTENT_DECODING_FAILED`)
- Limite : si Cloudflare est configuré pour afficher ses propres pages d'erreur (Custom Pages) ou intercepte les erreurs d'origine, la page brandée du WAF peut être masquée par celle de Cloudflare (hors périmètre du WAF)

## FR-40 — Terminaison TLS par domaine (sélection par SNI)

> Numérotée FR-33 jusqu'à la v3.9.0 : l'identifiant était déjà celui du moteur
> de scoring de risque (`requirements-detection.md`). Les entrées antérieures de
> `changelog.md`, `tasks.md` et `validation.md` qui citent « FR-33 » à propos du
> TLS par domaine désignent cette exigence.

> Étend FR-31. Permet au WAF de terminer le TLS en présentant un **certificat
> distinct par domaine**, sélectionné par SNI à partir de certificats existants
> sur disque (sans dépendre d'ACME). Décision : voir ADR-017.

- Quand `server.tls.enabled: true`, le WAF DOIT terminer le TLS et écouter en HTTPS sur `server.tls.listen` (défaut `:443`)
- Le WAF DOIT permettre de définir un certificat **par domaine** via `domains[].tls.cert_file` et `domains[].tls.key_file` (PEM sur disque)
- Le WAF DOIT sélectionner le certificat présenté en fonction du **SNI** (`ClientHello.ServerName`) :
  - correspondance **exacte** du `host` du domaine, OU
  - correspondance **wildcard** (`*.example.com`) selon les mêmes règles que le routage par `host` existant
- Le WAF DOIT charger toutes les paires cert/clé **au démarrage** et DOIT **refuser de démarrer** (fail-fast) si un fichier est manquant, illisible, mal formé, ou si la clé ne correspond pas au certificat
- Le WAF DOIT servir un certificat **par défaut** (`server.tls.cert_file` / `key_file`) pour un SNI sans correspondance, s'il est configuré ; **sinon** le handshake DOIT être refusé (`unrecognized_name`), sans servir silencieusement un certificat arbitraire
- Le WAF DOIT supporter **TLS 1.2 et 1.3**, avec un plancher configurable `server.tls.min_version` (défaut `1.2`), et refuser les versions inférieures
- Le WAF DOIT permettre une liste explicite de cipher suites (`server.tls.cipher_suites`), avec un défaut sécurisé si la liste est vide
- Quand `server.tls.redirect_http: true`, le WAF DOIT rediriger le trafic HTTP (`server.listen`) vers HTTPS en `301`, en préservant chemin et query
- `server.listen` (redirection) et `server.tls.listen` DOIVENT être des adresses distinctes quand `redirect_http` est actif : la configuration DOIT être refusée à la validation, et non au bind du second serveur (`address already in use`). Plus généralement, deux serveurs démarrés (public, redirection, challenge ACME, API admin) NE DOIVENT PAS partager une adresse ; ":443" et "0.0.0.0:443" désignent la même. La surcharge `-listen` est revalidée
- Le handler de redirection DOIT valider le `Host` entrant contre la liste des domaines configurés (exact ou wildcard) avant de rediriger, selon les règles du routage (un wildcard `*.example.com` couvre aussi l'apex `example.com`) ; un `Host` non reconnu DOIT recevoir `400 Bad Request` (protection contre l'open-redirect par injection de header `Host`)
- Le WAF DOIT exposer `waf_tls_cert_expiry_seconds{domain}` pour chaque certificat chargé (réutilise FR-31)
- Le WAF DEVRAIT recharger les certificats sans redémarrage (`SIGHUP`) — **optionnel**, hors première tranche
- Le renouvellement des certificats statiques est géré **hors WAF** (outillage amont) ; ACME (FR-31) reste un mécanisme complémentaire et n'est pas activé simultanément sur le même listener dans la première version

---

## Non-Functional Requirements additionnels (v3)

### NFR-11 — Connexions & Slowloris
- Timeout sur headers HTTP : `10s` par défaut (`slowloris.header_timeout`)
- Lecture complète de la requête : `30s` par défaut (`server.read_timeout`) ;
  un débit minimum du body est différé (FR-23)
- Max requêtes simultanées par IP : `50` par défaut

### NFR-12 — Webhooks Performance
- Envoi webhook : entièrement asynchrone, jamais bloquant pour la requête
- Délai max entre événement et envoi webhook : < 500ms (hors retry)

### NFR-13 — Health Checks Performance
- Health check goroutine : pool séparé, n'interfère pas avec le pool de traitement des requêtes
- Pas de health check vers l'upstream pendant le graceful shutdown

### NFR-14 — ACME/TLS
- Renouvellement automatique : déclenché ≥ 30 jours avant expiration
- Rotation de certificat sans interruption de service (swap atomique du tls.Config)

### NFR-17 — Store mémoire : pas de gel périodique
- Le nettoyage périodique du store (entrées expirées) NE DOIT PAS tenir le verrou
  global pendant tout le balayage : collecter les clés expirées sans verrou, puis
  supprimer par clé sous verrou court. Sinon le sweep fige toutes les requêtes
  (chaque requête prend le verrou) pendant sa durée.
- Les lectures du store (`GetVisitor`) NE DOIVENT PAS prendre de verrou en écriture
  sur le chemin chaud.
- Le nombre de buckets de rate-limit DOIT être borné (éviction des moins récemment
  rafraîchis) : ils n'ont pas d'éviction LRU propre et grossiraient sans limite.

### NFR-16 — Journalisation non bloquante
- L'écriture des événements de sécurité NE DOIT JAMAIS bloquer le goroutine de
  requête : tampon en mémoire + écriture stdout/stderr dans un goroutine de fond.
- Tampon plein (sortie lente : rotation, disque, pipe non consommé) → la ligne est
  abandonnée (compteur `dropped` exposé), jamais d'attente sur l'I/O.
- Rationale : une écriture bloquée figerait le middleware de log (le plus externe),
  retiendrait la connexion keep-alive, et provoquerait des timeouts en cascade via
  le pool de connexions partagé de Cloudflare vers l'origine.
