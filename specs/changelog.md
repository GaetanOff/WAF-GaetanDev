# Changelog — WAF Anti-DDoS / Anti-Bot

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

## [Unreleased]

### Changed

- **`architecture.md` (1.1.0 → 1.2.0) — remise à niveau sur le code réel.** Le
  `Request Processing Pipeline` décrivait 10 étapes de la v1 (`CF-IP → Whitelist →
  Blacklist → RateLimit → BotDetect → TrustScore → Challenge → Proxy → Logger`).
  Y manquaient `ingress`, `secheaders`, `maintenance`, `slowloris`,
  `staticassets`, `selfprotect`, `metrics`, `access`, les sept détecteurs de
  signal, le moteur de risque, `origin` et le tarpit — soit la moitié de la
  chaîne, dont l'intégralité de ce qui a été livré depuis la phase 8.
  - Les 21 étapes sont désormais listées **dans leur ordre d'exécution**, chacune
    avec **la clé de configuration qui la monte** : une étape non montée est
    absente de la chaîne, elle ne se contente pas de ne rien faire. C'est
    précisément ce que l'ancien diagramme ne permettait pas de voir.
  - Le document dit maintenant que `/waf/health`, `/waf/metrics` et
    `/waf/origin/verify` sont servis par le `mux` **sans traverser** les étapes
    [6] à [20] — un fait structurant qui n'apparaissait nulle part.
  - Sorties anticipées documentées (403, 429, 503, 400, page de challenge) et
    chemin de remontée de la réponse.
  - Renvois vers ADR-019 (les `CF-*` autres que `CF-Connecting-IP` ne sont pas
    validés) et ADR-020 (repli du routage par `Host`) posés aux deux étapes
    concernées, pour que le lecteur du diagramme voie les limites.
  - `C4 niveau 2` réécrit (bordures alignées, trois chemins `/waf/*` visibles),
    `C4 niveau 3` passé de 15 à **42 paquets** groupés par rôle, `Go Project
    Structure` corrigé — il annonçait un `middleware/chain.go` qui n'existe pas et
    un `configs/config.schema.json` qui vit en réalité dans `specs/schemas/`.
  - Index des ADR complété : il s'arrêtait à ADR-004, il couvre les 20, avec le
    statut affiché pour ceux qui ne sont pas `accepted`.

- **Montée du projet vers Go 1.27** : `go.mod` passe de `go 1.26.0` +
  `toolchain go1.26.5` à `go 1.27.0`. La directive `go` fait elle-même office de
  plancher de toolchain : `toolchain go1.26.5` devenait redondant (et donc
  susceptible de dériver), il est supprimé — go1.27.0 embarque le correctif
  GO-2026-5856 (fuite ECH dans `crypto/tls`) qui motivait ce pin.
  Propagation : image de build `golang:1.26-alpine` → `golang:1.27-alpine`
  (Dockerfile), commentaire golangci-lint du workflow CI. Le CI résout déjà la
  version via `go-version-file: go.mod` — aucun changement de workflow requis.
  Docs alignées : `mission.md`, `requirements.md`, conséquences d'ADR-001
  (le corps historique de l'ADR, `accepted`, reste inchangé).
- **FR-23 — nouvelle borne `server.max_header_value_count`** (défaut **100**,
  `0` = défaut Go 500) : câblée sur `http.Server.MaxHeaderValueCount`
  (Go 1.27) pour le listener public, le serveur de challenge ACME, le
  redirecteur HTTP→HTTPS et l'API admin. Complète `max_connections_per_ip` :
  cette dernière borne le nombre de requêtes concurrentes, la nouvelle borne le
  coût de parsing d'**une seule** requête portant des milliers de lignes
  d'en-tête. Le rejet a lieu dans `net/http`, avant tout middleware.
- **Dépendance `github.com/google/uuid` supprimée** au profit du paquet `uuid`
  de la stdlib (nouveau en Go 1.27). Le contrat « UUID v4 » d'`architecture.md`
  est désormais explicite dans le code (`uuid.NewV4()`) et vérifié par le test
  (version + variante RFC 9562).
- **FR-30 — parsing JSON durci sur les entrées non fiables** via
  `encoding/json/v2` (nouveau en Go 1.27), encapsulé dans `internal/jsonstrict` :
  - un **nom de membre dupliqué** est désormais rejeté (400). v1 appliquait
    « le dernier gagne » : le WAF lisait `"b"` dans `{"k":"a","k":"b"}` là où une
    origine appliquant « le premier gagne » lisait `"a"` — différentiel de
    parseur, vecteur classique de contournement ;
  - l'**UTF-8 invalide** est rejeté au lieu d'être remplacé par U+FFFD, qui
    faisait diverger la valeur inspectée de la valeur reçue sur le fil.
  - Appliqué à `POST /waf/verify` (public, non authentifié) et aux trois
    endpoints à corps de l'API admin. `MatchCaseInsensitiveNames(true)` conserve
    l'appariement v1 insensible à la casse et `RejectUnknownMembers(true)`
    reproduit `DisallowUnknownFields` : le **seul** changement observable est le
    rejet de JSON ambigu ou mal formé.
  - **Hors périmètre, délibérément** : les payloads déjà authentifiés par HMAC
    (cookie, nonce) — produits par le WAF lui-même ; le bus Redis inter-nœuds ;
    et la réponse AbuseIPDB, qui n'utilise pas `DisallowUnknownFields` et doit
    tolérer l'ajout de champs par le fournisseur.
- **Modernisations `go fix`** débloquées par la directive `go 1.27` :
  `min()`, `slices.Contains`, `slices.Backward`, `strings.Cut`, `for range N`.
  Changements mécaniques et sans effet sémantique, isolés dans leur propre commit.

### Fixed

- **FR-06 — `domains[].challenge_enabled` n'avait aucun effet** : la clé était
  documentée (CONFIG.md, `config.schema.json`) et désérialisée dans
  `config.DomainConfig`, mais **jamais lue**. Le challenge JS était monté et servi
  uniquement selon le `challenge.enabled` global : un domaine déclarant
  `challenge_enabled: false` recevait quand même la page de challenge, et un
  domaine déclarant `challenge_enabled: true` restait sans challenge si le global
  était à `false`.
  Le champ devient un **`*bool` à trois états** — absent = hérite du global,
  `false` = jamais de challenge sur ce domaine (y compris sous le mode « sous
  attaque » FR-39, décision explicite de l'opérateur qui prime sur l'escalade
  automatique), `true` = force le challenge même si le global est à `false`.
  Le `*bool` est indispensable : avec un `bool`, le zéro-valeur aurait désactivé
  le challenge sur toute entrée `domains[]` déclarée pour son seul `upstream` ou
  son certificat TLS — un fail-open silencieux.
  La résolution d'hôte réutilise les règles de routage `domains[]` (casse ignorée,
  port retiré, wildcard `*.example.com` couvrant l'apex, première correspondance
  gagnante). Le middleware est désormais monté dès qu'**au moins un** domaine
  active le challenge, même quand `challenge.enabled` est `false`.
  `POST /waf/verify` reste servi par le WAF sur tous les domaines : `/waf/` est un
  préfixe réservé, et un token est de toute façon lié à l'hôte émetteur.
- **FR-08/FR-05 (v2.1.0) — cascade de faux positifs sous pression** : pendant un
  DDoS, un visiteur légitime était tué en un clic. Le throttle de pression
  divisait aussi la **capacité de burst** (÷4 en critical) : un chargement de
  page (25-50 sous-requêtes) crevait le bucket → chaque 429 appliquait -10 au
  score jusqu'à BLOCKED (TTL 1 h) → les 429 nourrissaient le circuit-breaker
  (5 consécutifs → 403 pendant 300 s). Corrections de spec :
  - le throttle de pression réduit **uniquement le débit de refill**, jamais la
    capacité de burst (le débit soutenu distingue un bot, pas le burst initial) ;
  - un 429 imputable au seul throttle de pression est marqué
    `reason=rate_limit_pressure` et reste **neutre** (ni violation breaker, ni
    pénalité de score) ; un dépassement du débit nominal reste sanctionné ;
  - la pénalité de score rate-limit est bornée à **une par fenêtre de 10 s**
    (champ `last_rate_limit_penalty` dans visitor.schema.json) au lieu d'une
    par sous-requête refusée.

### Security

- **FR-17 — la condition `ip` du moteur de règles lisait `X-Real-IP`**, un en-tête
  **client**. `internal/rules/rules.go` était le **seul** endroit du dépôt à ne pas
  résoudre l'IP via `cloudflare.RealIP` : les 20 autres consommateurs (whitelist,
  blacklist, rate limit, trust score, anti-bot, anti-DDoS, threat intel, challenge,
  risque…) passent tous par le chemin de confiance. Conséquence : `X-Real-IP:
  8.8.8.8` faisait échapper un client réellement en `10.1.2.3` à une règle
  `ip in_cidr ["10.0.0.0/8"]` de blocage, et `X-Real-IP: <ip de confiance>`
  permettait d'usurper une règle d'attribution de score.
  - **Exploitable à travers Cloudflare** : contrairement à `CF-Connecting-IP`,
    `X-Real-IP` n'est ni posé ni réécrit par Cloudflare — la valeur du client
    traverse telle quelle. Aucun accès direct à l'origine n'est nécessaire.
  - `X-Real-IP` est un en-tête **sortant** que le proxy pose vers l'upstream
    (`internal/proxy/handler.go`) depuis l'IP réelle. Sa présence en **entrée**
    n'avait aucune signification : la lecture confondait les deux sens.
  - Corrigé en alignant `clientIP` sur `cloudflare.RealIP`, soit un seul chemin
    d'IP pour toutes les décisions du WAF.
- **Audit des surfaces de confiance implicite** (tâche ouverte de T14.1) — deux
  constats sortent du périmètre d'un correctif et attendent une décision
  d'opérateur, chacun son ADR en statut `proposed` :
  - **ADR-019** — les en-têtes d'infrastructure (`CF-IPCountry` pour FR-16 et le
    champ `country` de FR-17, `ja3_header` pour FR-11) sont honorés sans preuve
    que la requête vient bien de l'intermédiaire qui les pose. La forge n'est
    qu'un cas particulier : ces contrôles **dégradent gracieusement** quand
    l'en-tête est absent, donc l'omission suffit déjà. Quatre options, de
    l'assainissement sans rejet à une liste `trusted_proxies`.
  - **ADR-020** — l'en-tête `Host` pilote à la fois le routage et la politique par
    domaine. Un `Host` non listé retombe sur `upstream.address` **et** sur la
    politique globale : si le défaut pointe la même origine qu'un domaine durci,
    le durcissement est contournable par un en-tête. Aucune liaison non plus
    entre le SNI et le `Host` en TLS par domaine (FR-33).

- **FR-30 — contournement complet du pipeline par en-tête `X-WAF-*` forgé**
  (nouveau paquet `internal/middleware/ingress`). Les middlewares se coordonnent
  en posant des en-têtes `X-WAF-*` **sur la requête**, relus en aval ; rien ne les
  nettoyait à l'entrée, donc un client pouvait les fabriquer. `X-WAF-Action: PASS`
  est testé en court-circuit par le challenge (`internal/trust/score.go`), le rate
  limiting (`internal/middleware/ratelimit`), l'analyse d'intégrité
  (`internal/integrity`), le threat intel (`internal/threatintel`) et le moteur de
  règles (`internal/rules`) : un seul en-tête suffisait à traverser tout le WAF.
  Reproduit sur `routes()` avant correctif — visiteur sous le seuil, `Accept:
  text/html`, `X-WAF-Action: PASS` → **204 de l'upstream** au lieu de la page de
  challenge. Atteignable depuis Internet : les proxies amont, Cloudflare compris,
  ne filtrent pas les `X-*` arbitraires.
  - Le middleware supprime **tout** en-tête de préfixe `X-WAF-` et est câblé en
    position **la plus externe** de `routes()`, après `secheaders` — donc premier
    à l'exécution, avant que quoi que ce soit ne lise ces en-têtes.
  - Suppression **par préfixe** et non par liste nominative : les 16 en-têtes
    internes actuels sont couverts, et ceux ajoutés plus tard le sont d'office.
    Une liste nominative se désynchronise en silence, et l'oubli est un fail-open.
  - `net/http` canonicalise les clés de `http.Header`, donc `x-waf-action` comme
    `X-WAF-ACTION` sont couverts par le seul préfixe `X-Waf-` ; les tests le
    vérifient explicitement.
  - **Flux interne préservé** : les détecteurs (`integrity`, `geo`, `antiddos`,
    `ratelimit`, `antibot`, `tlsfp`, `behavioral`) posent leurs `X-WAF-Risk-*`
    *à l'intérieur* du pipeline, donc après ce middleware. Seul ce qui vient du
    client est retiré. `CF-Connecting-IP` (FR-02), les `X-Forwarded-*` et
    `Authorization` (FR-10) ne sont pas touchés.
  - Effet de bord assumé sur deux tests de `cmd/waf` qui **utilisaient la faille
    comme point d'injection** : ils posaient `X-WAF-Risk-*` sur la requête cliente
    pour piloter le moteur de risque. `TestRoutesAppliesRiskDecisionBeforeProxy`
    échouait franchement ; `TestRoutesRiskEngineShadowByDefault` passait pour la
    mauvaise raison (il vérifie que le proxy *est* appelé, ce qui devenait vrai
    trivialement). Les deux passent désormais par un détecteur du paramètre
    `detectors`, **comme en production**, et redeviennent significatifs.
  - **Régression FR-19 rattrapée dans la même PR** : l'assainissement cassait
    `GET /waf/origin/verify`, l'oracle que l'upstream appelle en lui retransmettant
    le `X-WAF-Origin-Token` reçu. Le token était supprimé avant le handler, donc
    l'endpoint répondait **401 à tout token, y compris valide** — la vérification
    de FR-19 devenait inopérante. Corrigé par une capture explicite avant
    l'assainissement (`origin.CaptureInboundToken`), lue hors de `r.Header` :
    l'exception ne porte que sur la lisibilité de la valeur, qui reste vérifiée
    par HMAC. Une exemption par **chemin** a été écartée : sa correction
    dépendrait d'une normalisation identique à celle du routeur.

- Alertes code-scanning n°35/36 (`go/clear-text-logging`, CWE-312, HIGH)
  **corrigées** : les en-têtes Cloudflare `CF-Ray` et `CF-IPCountry` étaient lus
  via le helper générique `optionalHeader(r, name)` au **nom d'en-tête variable**,
  puis journalisés tels quels dans l'événement de sécurité. CodeQL ne reconnaît
  pas une lecture d'en-tête au nom non constant comme « en-tête non sensible »
  (barrière `NonSensitiveHeaderGet`) et classait donc la valeur comme donnée
  sensible atteignant un sink de log — contrairement à `reason`, `risk_decision`
  ou `global_pressure`, lus avec un nom littéral et jamais signalés. Ces en-têtes
  sont par ailleurs **contrôlables par le client** si l'origine est jointe hors
  Cloudflare (accès direct). Correctifs (`internal/logger/middleware.go` ; contrat
  `security-event.schema.json` inchangé — `cf_ray`/`cf_country` restent
  `["string","null"]`) :
  - lecture via un **nom d'en-tête littéral constant** : c'est ce qui lève
    l'alerte (la barrière CodeQL s'applique) ;
  - défense en profondeur : `cf_ray` **filtré** sur un jeu de caractères sûr
    (alphanumériques ASCII + tiret) et borné à 32 caractères ; `cf_country`
    **validé** (2 lettres majuscules — ISO 3166-1 alpha-2 et `XX` — ou `T1`
    Cloudflare/Tor), sinon journalisé `null` plutôt que brut. Durcit aussi la
    valeur pays transmise au webhook Discord (texte brut).
  - Le journal d'audit transitant par le handler JSON de slog (échappement des
    caractères de contrôle), l'injection de fausses lignes (CWE-117) n'y était
    pas directement exploitable ; le filtrage protège les consommateurs de logs
    non-JSON en aval.
- Toolchain Go forcé à **`go1.26.5`** (directive `toolchain` dans `go.mod`) :
  corrige GO-2026-5856 (fuite de confidentialité Encrypted Client Hello dans
  `crypto/tls`, stdlib), **atteignable** dans le WAF (terminaison TLS,
  handshakes entrants/sortants) d'après l'analyse au niveau symbole de
  `govulncheck`.
- Alerte code-scanning n°32 (GO-2026-5932, `golang.org/x/crypto/openpgp`
  « unsafe by design ») classée **faux positif** : advisory au niveau package
  sans version corrigée, alors que le seul package importé du module est
  `acme/autocert` — `openpgp` n'est jamais compilé dans le binaire. Confirmé
  par `govulncheck`. Ajout d'un `.trivyignore` documenté, câblé dans le
  workflow Trivy (`trivyignores`).
- Montée de version des dépendances `golang.org/x` pour corriger 21 alertes de
  code-scanning (vulnérabilités connues) :
  - `golang.org/x/crypto` `v0.45.0` → `v0.52.0` (13 CVE, dont HIGH
    CVE-2026-46597/46595/42508/39835/39830/39829/39828/39827 et MEDIUM
    CVE-2026-46598/39834/39833/39832/39831).
  - `golang.org/x/net` `v0.47.0` → `v0.55.0` (7 CVE HIGH :
    CVE-2026-42506/42502/39821/33814/27136/25681/25680).
  - `golang.org/x/sys` `v0.38.0` → `v0.45.0` (CVE-2026-39824 ; `0.45.0` requis
    par crypto/net, couvre le fix `0.44.0`).
  - `golang.org/x/text` `v0.31.0` → `v0.37.0` (entraîné par MVS).
  Aucun changement d'API : build + suite de tests verts.

### Added

- FR-39 — Mode **« sous attaque »** (challenge forcé piloté par la pression).
  Comble la faille révélée par l'incident du 2026-06-19 : un flood applicatif (L7)
  **distribué** (chaque requête « propre », chaque IP sous sa limite) restait sous le
  palier `CHALLENGE` du moteur de risque et saturait l'origine. Sous pression avérée
  (`high`/`critical`, évaluée **par domaine** par défaut), le WAF force désormais le
  challenge JS de toute requête **sans clearance** (cookie `waf_session`, bot
  vérifié, whitelist, sticky trust) : le PoW filtre le botnet sans moteur JS tandis
  que les navigateurs réels et clients connus passent. Mitigation **réversible**
  (jamais de blocage dur seul, conforme ADR-016), avec **hystérésis** anti-battement
  (entrée `trigger_pressure`, sortie sous `exit_pressure` soutenu `cooldown`), portée
  **par domaine** (compteur de pression par domaine borné par LRU), et mode
  **shadow** (FR-38) pour calibration. Nouveau bloc `antiddos.under_attack` ;
  champ de log `under_attack` ; métriques `waf_under_attack{domain}` et
  `waf_under_attack_challenges_total{domain}` ; alerte FR-29 à l'entrée/sortie du
  mode. Activé par défaut (`enabled: true`). Implémenté Slice 12.1. Voir `ADR-018`,
  `requirements-detection.md` FR-39, `features/anti-ddos.feature`.
  - Les alertes de transition (`under_attack_start`/`_end`) sont envoyées en mode
    **`Immediate`** : elles contournent la déduplication par cooldown du Notifier.
    Sans cela, une **réactivation rapprochée** du mode (attaque en plusieurs vagues
    séparées d'un creux) dans la fenêtre de cooldown (ex. 5 min) n'était pas alertée.
    La cadence reste bornée par l'hystérésis du contrôleur (sortie sous
    `exit_pressure` soutenu `cooldown`).

### Changed

- Webhooks d'alerte (FR-29) — payload enrichi. Discord reçoit désormais un
  **embed** (couleur par sévérité, titre avec emoji, champs Domaine/Action/IP/
  Pays/Méthode/Chemin/Raison/Score, timestamp, footer avec request_id) au lieu
  d'un simple `content` texte ; Slack reçoit un **attachment** coloré équivalent ;
  le sink générique reçoit l'`Alert` JSON enrichie. L'événement source transporte
  maintenant IP, chemin, méthode, action, request_id, pays et score de confiance.
- Pages d'erreur (FR-32) — **refonte visuelle** de la page brandée par défaut
  (403/429/503/502…). Elle reprend désormais le design de la page d'accès
  (carte centrée, badge « Protected by GaetanDev.fr », **dark mode auto** via
  `prefers-color-scheme`) au lieu de la carte sombre générique, pour être
  « visuellement cohérente avec la page de challenge » (cf.
  `features/maintenance-page.feature`). L'icône est une **croix rouge animée**
  (miroir de la coche verte de la page d'accès autorisé) : apparition « pop » du
  cercle puis tracé du trait, neutralisée si `prefers-reduced-motion: reduce`.
  100 % CSS inline, sans ressource externe ni JavaScript. Aucun changement de
  contrat (statuts, messages `messageFor`, branding, en-têtes inchangés).
- Pages d'erreur (FR-32) — le remplacement du corps d'erreur 4xx/5xx par la page
  HTML brandée ne s'applique plus qu'aux **navigations de navigateur**
  (`Accept: text/html`). Les appels API/XHR (`application/json`, `*/*`, ou Accept
  absent) conservent leur corps d'erreur d'origine (souvent JSON), pour que les
  clients `fetch`/`axios` puissent le parser. La page de maintenance forcée (503)
  reste servie à tous.
- Anti-bot (FR-07) — respect de `risk_engine.shadow_mode` : en calibration, les
  blocages **heuristiques** (UA d'automation, headers navigateur manquants…) sont
  observés et publiés au moteur de risque sans être appliqués, pour ne pas casser
  le trafic API/serveur légitime non-navigateur. Le **honeypot** (déterministe)
  reste bloquant même en shadow. `antibot.New` prend désormais un paramètre `shadow`.
- Challenge JS (FR-06) — la page de challenge suit désormais **automatiquement le
  thème système** du visiteur via `@media (prefers-color-scheme: dark)` : fond
  clair par défaut, bascule en thème sombre (`#121212`/`#1e1e1e`, texte clair)
  quand le navigateur/OS est en mode sombre. 100 % CSS, sans JavaScript ni bouton
  de sélection, aucune ressource externe, aucune préférence stockée côté WAF. Le
  badge « Protected by » (styles inline) est passé en classe `.footer-badge` pour
  être thémable. Voir `features/js-challenge.feature`.
- Challenge JS (FR-06) — servi uniquement pour une **navigation de navigateur**
  (`GET`/`HEAD` + `Accept: text/html`). Les appels API/XHR (`fetch`, `axios`,
  mobile) contournent le challenge au lieu de recevoir une page HTML qu'ils ne
  peuvent pas exécuter ; ils restent couverts par le rate-limit et le moteur de
  risque.
- Challenge JS (FR-06) — plancher de timing désactivé par défaut :
  `challenge.min_elapsed_ms` passe de `500` à `0` et `max_elapsed_ms` de `10000`
  à `60000`. Sur un client rapide la PoW se résout en quelques dizaines de ms ;
  le plancher à 500 ms rejetait ces résolutions légitimes (`challenge_too_fast`)
  → boucle de challenge. La résistance anti-bot vient de la PoW + fingerprint +
  cookie, pas du chrono. Un opérateur peut réactiver un plancher (`> 0`).

### Fixed

- `waf_latency_ms` (FR-09) — mesure désormais le temps réellement passé **dans le
  WAF** (`latency_ms` total − temps upstream), au lieu d'être un doublon exact de
  `latency_ms`. Un nouveau chronomètre (`internal/upstreamtime`, porté par le
  contexte de requête) est alimenté par le proxy autour de l'appel upstream
  (round-trip + streaming) ; le middleware de log le soustrait. Permet enfin de
  distinguer l'overhead WAF de la latence d'origine (ex: un stream SSE de 135s
  n'affiche plus 135000 en `waf_latency_ms`).
- Classification d'action (FR-09) — un statut **5xx/4xx provenant de l'upstream**
  (origine down → 502, ou 403/404 applicatif) n'est plus étiqueté `BLOCK`.
  `actionFromStatus` mappait tout `≥500`/`403` en blocage WAF, alors que toutes
  les vraies décisions du WAF posent `X-WAF-Action`. Sans cet en-tête, l'action
  est désormais `PASS` avec le vrai `upstream_status`. Corrige : faux `BLOCK` dans
  `waf_blocked_total`, fausses **alertes webhook** à chaque hoquet d'origine, et
  `upstream_status` masqué (`null`) sur ces réponses.
- Store mémoire (NFR-17) — le nettoyage périodique (`CleanupExpired`, toutes les
  60s) ne tient plus le verrou global pendant tout le balayage : il collecte les
  clés expirées sans verrou puis supprime par clé sous verrou court. Avant, le
  sweep tenait `s.mu` pendant tout le parcours des maps visitors + buckets, ce qui
  figeait toutes les requêtes (chacune prend `s.mu` à chaque `GetVisitor`) pendant
  sa durée → micro-gels périodiques sous charge. De plus : `GetVisitor` ne prend
  plus de verrou (lecture lock-free, éviction « least-recently-set »), et la map
  des buckets de rate-limit est désormais bornée (éviction des moins récemment
  rafraîchis) au lieu de grossir indéfiniment.
- Journalisation non bloquante (FR-09, NFR-16) — l'écriture des événements de
  sécurité passe par un tampon + un goroutine de fond (`asyncWriter`). Avant,
  `slog` écrivait sur `os.Stdout` de façon synchrone dans le middleware de log
  (le plus externe) : si le consommateur de stdout ralentissait (rotation Docker,
  disque, pipe non lu), le goroutine de requête se figeait, la connexion
  keep-alive n'était pas libérée, et Cloudflare (pool de connexions partagé)
  accumulait des timeouts en cascade sur des services aléatoires. Désormais le
  chemin de requête ne bloque jamais sur l'I/O de log ; à saturation les lignes
  sont abandonnées (compteur `Dropped()`).
- Pages d'erreur (FR-32) — les erreurs **5xx** (502/503/504) sont désormais
  brandées **même quand le corps est déjà en HTML** : quand l'origine est down,
  un reverse proxy en aval (nginx/OpenResty) renvoie sa page « 502 Bad Gateway »
  générique en `text/html` ; elle est maintenant remplacée par la page WAF
  brandée (sur navigation navigateur). Les **4xx** restent brandés uniquement si
  non-HTML, pour préserver les pages d'erreur HTML légitimes des applications.
- Challenge JS (FR-06) : la page de challenge et les réponses `/waf/verify`
  (succès et erreur) sont désormais non-cacheables (`Cache-Control: no-store`,
  `Pragma: no-cache`, `Expires: 0`). Sans cela, un CDN en « Cache Everything »
  (ex: Cloudflare) pouvait figer un token de challenge expiré et lié à une IP
  pour tous les visiteurs, provoquant une boucle de challenge infinie.

### Added

- `upstream.preserve_host` (FR-01) — conserve l'en-tête `Host` entrant vers
  l'upstream au lieu de le réécrire vers l'hôte de l'upstream. Requis quand
  l'upstream route par `server_name` (nginx/OpenResty en aval). Défaut `false`
  (comportement historique). S'applique au routage par domaine et au pool
  d'upstreams (`WithPool`).

### Fixed

- Redirection HTTP→HTTPS (FR-33) — protection contre l'**open-redirect** par
  injection de header `Host` et par chemin double-slash. Le handler valide
  désormais le `Host` entrant contre la liste des domaines configurés (exact +
  wildcard) avant de rediriger ; un host non reconnu reçoit `400 Bad Request`.
  L'URL cible est construite via `url.URL{Scheme, Host, Path, RawQuery}` au
  lieu d'une concaténation de strings : un chemin `//evil.com/x` ne peut plus
  parasiter le host dans l'URL de redirection.


- FR-33 — Terminaison **TLS par domaine** (sélection par SNI) : le WAF peut
  terminer le TLS en présentant un certificat distinct par domaine
  (`domains[].tls.cert_file`/`key_file`), choisi selon le SNI (exact + wildcard),
  à partir de certificats existants sur disque (sans dépendre d'ACME). Nouveau
  bloc `server.tls` (enabled, listen, min_version, cipher_suites, redirect_http,
  cert/clé par défaut), package `internal/tlsmgr`, métrique
  `waf_tls_cert_expiry_seconds{domain}`, redirection HTTP→HTTPS, et fail-fast au
  démarrage (cert manquant / clé non concordante). Un SNI sans correspondance et
  sans cert par défaut provoque un refus de handshake. Mutuellement exclusif avec
  ACME sur le même listener. Voir `ADR-017`, `requirements-ops.md` FR-33,
  `features/per-domain-tls.feature`. (Slice 11.1)

### Changed

- FR-08 Anti-DDoS passe du mode degrade global `503` a un mode
  de pression adaptative (`normal` / `elevated` / `high` / `critical`). Le
  trafic global ne doit plus produire de blocage automatique ; il renforce les
  mitigations reversibles (challenge, throttling, PoW adaptatif) et alimente le
  moteur de risque. Voir `ADR-016`.

Spécifications rédigées et approuvées, implémentation à venir (voir
`specs/requirements-advanced.md` et `specs/requirements-ops.md`) :

- TLS/JA3 fingerprinting, analyse comportementale, threat intelligence
- Difficulté de PoW adaptative, couche de déception (tarpit + honeypot)
- Moteur de règles YAML, règles géographiques, intégrité de requête
- Protection de l'origine, synchronisation multi-nœuds (Redis)
- En-têtes de sécurité, protection Slowloris, bypass des assets statiques
- Health checks upstream + load balancing, audit trail, conformité RGPD
- Webhooks d'alerte, auto-protection du WAF, ACME/Let's Encrypt
- Moteur de scoring de risque & décision graduée (implémenté, voir
  `specs/requirements-detection.md` v1.0.0 et `ADR-015`) : fusion pondérée des
  signaux, corroboration (≥ 2 familles pour un BLOCK), mitigation réversible
  (ALLOW → OBSERVE → THROTTLE → CHALLENGE → TARPIT → BLOCK), allowlist de bots
  vérifiés (reverse-DNS), crédits de preuve humaine, mode shadow et boucle de
  feedback faux positifs (objectif FP < 0,1 %).
  - Câblé sur les détecteurs déjà implémentés (familles `reputation`,
    `fingerprint`, `rate`). Les familles avancées (`behavioral`, `tls`,
    `geo`, `integrity`, threat-intel) seront alimentées par les détecteurs de
    la Phase 8. **Actif en mode shadow par défaut** (calibration NFR-15).

## [0.1.0] - 2026-06-04

Première version : WAF reverse proxy de base, fonctionnel et testé
(Sprints 1 à 5 du plan d'implémentation).

### Added

- **Reverse proxy** Go multi-domaine (routing par `Host`), injection
  `X-Forwarded-For` / `X-Real-IP` / `X-WAF-Score`, timeouts configurables,
  réponse `502` propre si l'origine est indisponible.
- **Extraction IP Cloudflare** : `CF-Connecting-IP` utilisé uniquement si la
  source appartient aux plages Cloudflare (rejet `400` sinon).
- **Whitelist / Blacklist** : IP exactes, CIDR et regex user-agent ;
  whitelist prioritaire, blacklist → `403`.
- **Rate limiting** token bucket par IP (`429` + `Retry-After`).
- **Score de confiance** par visiteur [0..100] avec états TRUSTED / MONITORED /
  CHALLENGED / BLOCKED, TTL et clamp.
- **Challenge JavaScript** sans CAPTCHA : Proof-of-Work SHA-256 (SubtleCrypto),
  fingerprint navigateur (9 signaux), contrainte de timing, page de challenge
  brandée « Protected by GaetanDev.fr » avec chronomètre.
- **Cookie de session** signé HMAC-SHA256 lié à l'IP, au domaine et à
  l'empreinte navigateur.
- **Anti-bot** : détection headless (SwiftShader, llvmpipe), user-agents
  suspects, chemins honeypot.
- **Anti-DDoS** : circuit breaker par IP + mode dégradé global (`503`) au-delà
  d'un seuil de trafic.
- **Observabilité** : logs JSON structurés (`log/slog`, stdlib) corrélés par
  `request_id`, métriques Prometheus sur `/waf/metrics`.
- **API d'administration** REST authentifiée par Bearer sur un port séparé
  (CRUD whitelist/blacklist, visiteurs, stats, events).
- **Configuration** YAML validée au démarrage, secrets via variables
  d'environnement.
- **Conteneurisation** : Dockerfile multi-stage (image distroless < 30 MB),
  `docker-compose.yml` de test (WAF + nginx d'origine), `HEALTHCHECK` intégré.
- **CI** GitHub Actions : lint, tests `-race` + couverture, build statique
  Linux, lint du contrat OpenAPI (spectral).
- **Documentation** : `README.md`, guide nginx d'origine, configuration
  d'exemple commentée.

[Unreleased]: https://github.com/GaetanOff/WAF-GaetanDev/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/GaetanOff/WAF-GaetanDev/releases/tag/v0.1.0
