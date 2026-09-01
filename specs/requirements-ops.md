---
status: approved
version: 3.3.0
last-reviewed: 2026-09-01
extends: requirements-advanced.md (v2.0.0)
change: "FR-30 : principe général — aucune décision de sécurité ne DOIT reposer sur un en-tête dont le WAF ne peut pas prouver l'origine. Les en-têtes d'infrastructure (`CF-*`, `ja3_header`) et `Host` sont renvoyés à ADR-019 et ADR-020, tous deux proposed"
---

# Requirements Ops — WAF Anti-DDoS / Anti-Bot (v3)

> Ce document comble les gaps opérationnels et de conformité identifiés à l'audit.
> IDs FR-21 à FR-33 font suite aux FR-01 à FR-20.

---

## FR-21 — Security Headers Injection

- Le WAF DOIT injecter des security headers dans **toutes** les réponses transmises au client
- Headers injectés par défaut (configurables et désactivables) :
  | Header | Valeur par défaut | Description |
  |--------|------------------|-------------|
  | `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Force HTTPS |
  | `X-Frame-Options` | `SAMEORIGIN` | Clickjacking protection |
  | `X-Content-Type-Options` | `nosniff` | MIME-type sniffing protection |
  | `Referrer-Policy` | `strict-origin-when-cross-origin` | Contrôle des données de référent |
  | `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | Feature policies |
  | `X-XSS-Protection` | `1; mode=block` | Compatibilité navigateurs anciens |
- Le WAF DOIT supporter une **Content-Security-Policy** configurable par domaine (valeur vide = header non injecté)
- Si l'upstream envoie déjà un header, le WAF NE DOIT PAS l'écraser (upstream a la priorité)
- Le WAF DOIT permettre de désactiver chaque header individuellement par domaine
- Le WAF DOIT injecter `X-WAF-Protected: GaetanDev.fr/1.0` (header de signature, désactivable)

## FR-22 — Response Sanitization (Masquage d'informations)

- Le WAF DOIT **supprimer ou remplacer** les headers qui révèlent l'infrastructure upstream :
  - `Server: nginx/1.25.3` → supprimé ou remplacé par valeur configurable
  - `X-Powered-By: PHP/8.2.0` → supprimé
  - `X-Generator: WordPress 6.4` → supprimé
  - `X-AspNet-Version: 4.0` → supprimé
  - `X-AspNetMvc-Version: 5.0` → supprimé
- Le WAF DOIT masquer les détails d'erreur dans les réponses 5xx de l'upstream :
  - Si `sanitize_errors: true` et réponse upstream est 500/502/503/504 avec body HTML contenant des stack traces ou chemins de fichiers → remplacer le body par une page d'erreur générique configurable
- La liste des headers à supprimer DOIT être configurable (`sanitize_headers: [...]`)
- Le comportement DOIT être opt-in par domaine (défaut: activé globalement)

## FR-23 — Protection Slowloris & Slow HTTP

- Le WAF DOIT implémenter une protection contre les attaques **Slowloris** (slow headers) :
  - Timeout sur la réception complète des headers HTTP : configurable (défaut `headers_timeout: 10s`)
  - Si les headers ne sont pas complets dans ce délai → fermer la connexion avec HTTP 408
- Le WAF DOIT implémenter une protection contre les attaques **Slow POST** (slow body) :
  - Timeout sur la réception du body avec un débit minimum configurable (défaut: 100 bytes/seconde)
  - Si le body arrive plus lentement que le seuil minimum → HTTP 408
- Le WAF DOIT limiter le nombre de connexions simultanées par IP :
  - `max_connections_per_ip`: configurable (défaut: 50)
  - Au-delà → TCP RST ou HTTP 429 selon config
- Le WAF DOIT détecter les connexions qui consomment le pool sans envoyer de données :
  - Connexions ouvertes > `idle_read_timeout` sans byte reçu → fermer
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

- Le WAF DOIT bypasser tous les middlewares de sécurité (challenge, trust score, rate limit) pour les **assets statiques connus** :
  - Par extension : `.css`, `.js`, `.map`, `.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.svg`, `.ico`, `.woff`, `.woff2`, `.ttf`, `.eot`
  - Par path prefix configurable : `/static/`, `/assets/`, `/public/`, `/dist/`
  - Par path exact configurable (ex: `/favicon.ico`, `/robots.txt`, `/sitemap.xml`)
- Le WAF DOIT tout de même vérifier la whitelist/blacklist pour les assets (les IPs blacklistées ne peuvent pas accéder aux assets)
- Le WAF NE DOIT PAS servir de page de challenge pour une requête d'asset statique
- Le WAF DOIT compter les requêtes d'assets dans les métriques (`waf_asset_requests_total`)
- La liste des extensions d'assets DOIT être configurable et extensible
- En cas de doute (path ambigu), le WAF DOIT traiter comme non-asset (sécurité > perf)

## FR-25 — Upstream Health Checks & Failover

- Le WAF DOIT effectuer des **health checks actifs** sur chaque upstream configuré :
  - Méthode : HTTP GET ou HEAD sur un path configurable (défaut: `/`)
  - Intervalle configurable (défaut: `10s`)
  - Timeout du health check : configurable (défaut: `3s`)
  - Nombre de succès requis pour marquer un upstream sain (défaut: 1)
  - Nombre d'échecs consécutifs pour marquer un upstream indisponible (défaut: 3)
- Quand un upstream est marqué **indisponible** :
  - Les nouvelles requêtes reçoivent une page de maintenance configurable (HTTP 503) — voir FR-32
  - Si un **upstream de secours** (`backup`) est configuré, basculer automatiquement
  - Un log event est émis : `action=UPSTREAM_DOWN` + métrique `waf_upstream_health{domain, status}`
- Quand l'upstream redevient disponible (N succès consécutifs) :
  - Reprendre le proxying normalement
  - Log event : `action=UPSTREAM_UP`
- Le WAF DOIT exposer l'état des upstreams via `GET /waf/admin/upstreams`

## FR-26 — Load Balancing Multi-Upstream

- Le WAF DOIT supporter un **pool d'upstreams** par domaine avec plusieurs stratégies :
  - `round_robin` : rotation à tour de rôle (défaut)
  - `least_conn` : upstream avec le moins de connexions actives
  - `random` : sélection aléatoire uniforme
  - `ip_hash` : même IP toujours routée vers le même upstream (sticky sessions)
- Chaque upstream du pool DOIT avoir un **poids** configurable (`weight: N`)
- Le WAF DOIT exclure automatiquement les upstreams indisponibles (intégré avec FR-25)
- Si tous les upstreams sont indisponibles → page de maintenance (FR-32)
- Le WAF DOIT exposer les métriques par upstream : `waf_upstream_requests_total{upstream}`, `waf_upstream_response_time_seconds{upstream}`

## FR-27 — Audit Trail des Actions Admin

- Le WAF DOIT maintenir un **journal d'audit immuable** de toutes les actions sur l'API admin :
  - Champs : `timestamp`, `action`, `endpoint`, `method`, `request_body` (secrets masqués), `response_status`, `client_ip`
  - Exemples : ajout en blacklist, modification config, reset visiteur, activation/désactivation règle
- Le journal DOIT être accessible via `GET /waf/admin/audit?since=&limit=`
- Le journal DOIT être **append-only** en mémoire (pas de suppression via API)
- La taille max du journal en mémoire DOIT être configurable (défaut: 10 000 entrées, rotation FIFO)
- En option, le journal DOIT pouvoir être écrit sur disque (fichier JSON-lines configurable)
- Toute action admin NE DOIT PAS être effectuée sans être journalisée (atomicité log + action)

## FR-28 — Conformité GDPR & Privacy

- Le WAF DOIT supporter un mode **IP anonymisation** (`privacy.anonymize_ip: true`) :
  - IPv4 : masquer le dernier octet (`192.168.1.x`)
  - IPv6 : masquer les 80 derniers bits
  - Quand actif, les logs et le store utilisent l'IP anonymisée (sauf audit trail)
- Le WAF DOIT supporter une **politique de rétention des données** :
  - `privacy.data_retention_hours` : durée max de conservation des `VisitorState` (défaut: 24h, configurable)
  - `privacy.event_retention_hours` : durée max des events de sécurité en mémoire (défaut: 24h)
  - Suppression automatique par goroutine de purge
- Le WAF DOIT fournir un endpoint `DELETE /waf/admin/visitors/{ip_hash}` pour le **droit à l'effacement** (déjà dans FR-10 mais formalisé ici avec audit log)
- Le WAF NE DOIT PAS logger les query parameters en clair dans les logs `info` et `warn` (déjà couvert en FR-09 mais formalisé)
- Le WAF DOIT documenter dans le README quelles données personnelles sont traitées et pour quelle durée (registre de traitement)
- En mode anonymisation, les fingerprints sont toujours hashés (comportement inchangé — privacy by design)

## FR-29 — Alerting & Webhooks

- Le WAF DOIT supporter l'envoi de **webhooks** sur des événements de sécurité configurables :
  - Format : HTTP POST vers une URL configurée, body JSON (voir `schemas/alert.schema.json`)
  - Retry : 3 tentatives avec backoff exponentiel (1s, 5s, 25s)
  - Timeout par appel : 5s
- **Triggers configurables** :
  | Trigger | Description |
  |---------|-------------|
  | `ddos_detected` | Taux de trafic > seuil configurable |
  | `upstream_down` | Upstream passe indisponible |
  | `circuit_breaker_open` | Circuit-breaker ouvert pour une IP |
  | `honeypot_triggered` | Visite d'un chemin honeypot |
  | `score_flood` | > N visiteurs en état BLOCKED en X secondes |
  | `challenge_flood` | > N soumissions /waf/verify en X secondes |
  | `rule_triggered` | Match d'une règle configurée comme alertante |
- **Intégrations prêtes à l'emploi** :
  - Slack (format Slack Incoming Webhook)
  - Discord (format Discord Webhook)
  - Generic HTTP (JSON libre, configurable)
- Le WAF DOIT exposer les métriques d'alertes : `waf_alerts_sent_total{trigger}`, `waf_alerts_failed_total`
- Les webhooks NE DOIVENT PAS bloquer le pipeline de traitement des requêtes (exécution asynchrone via channel)

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
  **d'infrastructure** posés par un intermédiaire (`CF-*`, `ja3_header`,
  `X-Forwarded-*`) et l'en-tête `Host` relèvent d'ADR-019 et ADR-020, tous deux
  `proposed` — leurs options rejetteraient du trafic aujourd'hui accepté et
  attendent une décision d'opérateur. Tant qu'elles ne sont pas tranchées, les
  contrôles qui en dépendent (FR-16 géo, FR-11 blacklist JA3, durcissement par
  domaine de FR-06) DOIVENT être documentés comme des contrôles de réduction de
  bruit, pas comme des frontières de sécurité

### Protection de l'endpoint /waf/verify
- Le WAF DOIT appliquer un rate limit strict sur `POST /waf/verify` : configurable (défaut: 10 req/s par IP)
- Toute IP qui dépasse ce rate limit sur `/waf/verify` est automatiquement blacklistée pour 1h
- Le WAF DOIT détecter les soumissions de challenge avec des tokens identiques (replay attack) et bloquer l'IP

### Protection de l'API Admin
- L'API admin DOIT implémenter un rate limit sur les tentatives d'authentification : défaut 5 req/min par IP
- Après 10 échecs d'authentification depuis la même IP en 5 minutes → IP blacklistée sur le port admin pour 24h
- Les échecs d'authentification DOIVENT être journalisés dans l'audit trail

### Protection de l'endpoint /waf/metrics
- `/waf/metrics` DOIT être protégeable par token (optionnel, désactivé par défaut pour faciliter Prometheus scraping)
- Sinon, accessible seulement depuis les IPs whitelistées ou le réseau interne

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
- Les charges utiles dont l'authenticité est déjà établie par HMAC (cookie de
  session, nonce) et les réponses d'API tierces sont **hors périmètre** : les
  premières sont produites par le WAF lui-même, les secondes doivent tolérer
  l'ajout de champs par le fournisseur

### Protection globale du WAF
- Le WAF DOIT détecter les **amplification attacks** sur le challenge : un visiteur qui génère plus de N tokens de challenge sans jamais les soumettre (stocke des nonces en mémoire) → ses nonces sont supprimés et il est challengé plus sévèrement
- Limite du store de nonces : `challenge.max_pending_nonces` par IP (défaut: 5)

## FR-31 — TLS Termination & ACME/Let's Encrypt

- Quand le WAF est configuré pour terminer TLS (`server.tls.enabled: true`) :
  - Le WAF DOIT supporter des certificats statiques (cert + key file) configurable
  - Le WAF DOIT supporter **ACME/Let's Encrypt** avec renouvellement automatique (≥ 30 jours avant expiration)
  - Le défi ACME `HTTP-01` DOIT être géré automatiquement (bypass du challenge WAF pour les paths `/.well-known/acme-challenge/`)
  - Le défi ACME `TLS-ALPN-01` DOIT être optionnellement supporté
  - Les certificats DOIVENT être stockés sur disque (path configurable) et rechargés sans redémarrage
  - Une métrique `waf_tls_cert_expiry_seconds{domain}` DOIT être exposée
- Le WAF DOIT supporter **TLS 1.2 et 1.3** côté client, configurable
- Le WAF DOIT supporter la configuration des cipher suites (liste configurable avec défaut sécurisé)
- Certificat expirant dans < 7 jours → alert webhook (FR-29)

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
- Pour les erreurs **5xx** (502/503/504 : origine/passerelle en panne), le WAF DOIT remplacer le corps **même s'il est déjà en HTML** : une page d'erreur générique d'un reverse proxy en aval (nginx/OpenResty) n'est pas du contenu applicatif à préserver. Pour les **4xx**, le WAF NE DOIT remplacer que les corps **non-HTML**, afin de préserver les pages d'erreur ou le JSON légitimes des applications
- Limite : si Cloudflare est configuré pour afficher ses propres pages d'erreur (Custom Pages) ou intercepte les erreurs d'origine, la page brandée du WAF peut être masquée par celle de Cloudflare (hors périmètre du WAF)

## FR-33 — Terminaison TLS par domaine (sélection par SNI)

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
- Le handler de redirection DOIT valider le `Host` entrant contre la liste des domaines configurés (exact ou wildcard) avant de rediriger ; un `Host` non reconnu DOIT recevoir `400 Bad Request` (protection contre l'open-redirect par injection de header `Host`)
- Le WAF DOIT exposer `waf_tls_cert_expiry_seconds{domain}` pour chaque certificat chargé (réutilise FR-31)
- Le WAF DEVRAIT recharger les certificats sans redémarrage (`SIGHUP`) — **optionnel**, hors première tranche
- Le renouvellement des certificats statiques est géré **hors WAF** (outillage amont) ; ACME (FR-31) reste un mécanisme complémentaire et n'est pas activé simultanément sur le même listener dans la première version

---

## Non-Functional Requirements additionnels (v3)

### NFR-11 — Connexions & Slowloris
- Timeout sur headers HTTP : `10s` par défaut (configurable `1s-60s`)
- Débit minimum du body : `100 B/s` par défaut (configurable)
- Max connexions simultanées par IP : `50` par défaut

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
