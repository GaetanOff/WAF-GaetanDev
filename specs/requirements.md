---
status: implemented
version: 2.8.4
last-reviewed: 2026-10-02
reviewed-by: GaetanDev
change: "FR-06 : avec les défauts, token_ttl (30 s) borne la durée du challenge avant max_elapsed_ms (60 s) — challenge_timeout n'est atteint que si max_elapsed_ms < token_ttl. Précédent (2.8.3) — FR-08 : le « challenge plus fréquent » sous pression est le mode sous attaque (FR-39) ; sous trigger_pressure, seule la contribution rate du moteur agit. Précédent (2.8.2) — FR-01 : le préfixe /waf/ est réservé — un chemin inconnu ou un endpoint désactivé sous /waf/ reçoit 404 du WAF, jamais transmis à l'upstream (/waf/stats et /waf/admin/* l'étaient). Précédent (2.8.1) — FR-01 : X-Forwarded-For vaut l'IP réelle du client (et non celle du PoP Cloudflare) ; X-Forwarded-Proto le schéma vu par le client (CF-Visitor derrière Cloudflare). Précédent (2.8.0) — FR-07 : le honeypot bannit le visiteur pour trust.score_ttl (honeypot_until, 403 BLOCK honeypot_ban, avant le challenge), moteur de risque actif ou non, shadow et assets compris ; /admin.php retiré des honeypot_paths par défaut ; shadow_mode sans effet sur l'anti-bot sans moteur de risque. FR-05 : « navigation normale (+1/req) », jamais implémenté, retiré. Précédent (2.7.1) — FR-10 : GET /waf/health de l'API admin répond degraded quand Redis sert l'état local ; le health public reste ok. Précédent (2.7.0) — NFR-04 : un panic d'un handler public ou admin est récupéré par le WAF — journal error avec request_id, compteur waf_panics_total, 500 si aucun en-tête n'est parti. Précédent (2.6.9) — FR-02 : l'anti-brute-force de l'API admin (FR-30) suit l'identité client (IPv6 par /64). Précédent (2.6.8) — FR-04 : une IPv4 mappée en IPv6 (::ffff:a.b.c.d) est évaluée comme l'IPv4 par la whitelist et la blacklist, adresse cliente comme entrée de liste. Précédent (2.6.7) — FR-01 : les en-têtes X-WAF-* d'une réponse de l'upstream sont supprimés — ils se lisaient comme une décision du WAF (violation FR-08, action et raison FR-09). Précédent (2.6.6) — FR-06 : la page de challenge porte une Content-Security-Policy stricte à nonce. Précédent (2.6.5) — FR-09 : événements de log abandonnés exposés (waf_log_events_dropped_total). Précédent (2.6.4) — FR-06 : la durée du challenge est mesurée par le serveur depuis l'émission signée du token ; elapsed_ms du client devient indicatif. Précédent (2.6.3) — NFR-03 : server.admin_listen vaut 127.0.0.1:9090 par défaut (boucle locale) au lieu de toutes les interfaces. Précédent (2.6.2) — NFR-03 : clé AbuseIPDB (WAF_ABUSEIPDB_KEY) et URL de webhook (WAF_ALERTING_WEBHOOKS_<i>_URL) configurables par l'environnement. Précédent (2.6.1) — FR-05 : les écritures de l'état d'un visiteur sont atomiques (compare-and-set Redis) — une pénalité concurrente n'est plus écrasée. Précédent (2.6.0) — FR-02 : identité client des contrôles par IP — une IPv6 compte par son /64 (rate limit, score, breaker, slowloris, auto-protection, ip_hash). Précédent (2.5.1) — FR-06 : token de challenge et cookie de clearance signés avec des clés dérivées distinctes — le token, remis à tout visiteur, se validait comme cookie et franchissait le challenge sans PoW. Précédent (2.5.0) — FR-01 : seuls X-WAF-Score et X-WAF-Origin-Token sont transmis à l'upstream, les autres X-WAF-* restent internes. Précédent (2.4.2) — FR-03 : les limites par domaine et par route sont différées, conformément à ADR-022 (la surcharge inerte a été retirée) ; FR-03 les exigeait encore. Précédent (2.4.1) — NFR-05 : arrêt parallèle de tous les serveurs, chacun avec le délai de grâce entier, y compris sur échec d'un listener. Précédent (2.4.0) — FR-09 : les refus slowloris, flood de /waf/verify et strict_host sont journalisés et comptés. FR-07 : un User-Agent de `whitelist_user_agents` n'est plus pénalisé par les heuristiques « client non navigateur » (en-têtes manquants, UA d'outil) — Googlebot était bloqué en huit requêtes. Précédent (2.3.2) — FR-09 : le label `domain` des métriques est borné aux hôtes de `domains[]`, tout autre hôte est compté sous `_undeclared`. Précédent (2.3.1) — FR-08 : seul un refus du rate limit du WAF (`X-WAF-Action: RATE_LIMIT`) est une violation de circuit-breaker, jamais un 429 de l'upstream. Précédent (2.3.0) — FR-02 / FR-03 / FR-09 : les clés de configuration inertes deviennent des exigences précises — rafraîchissement des plages IP Cloudflare (source, validation, repli), fenêtres req/minute et req/heure du rate limiting, et contrat des deux formats de journalisation (`json` = contrat d'audit, `pretty` = rendu console de développement)"
---

# Requirements — WAF Anti-DDoS / Anti-Bot

## Functional Requirements

### FR-01 — Reverse Proxy
- Le WAF DOIT agir comme reverse proxy HTTP/1.1 et HTTP/2
- Le WAF DOIT transmettre les requêtes légitimes vers l'upstream configuré
- Le WAF DOIT préserver tous les headers originaux et ajouter `X-Forwarded-For`, `X-Real-IP`
  - `X-Forwarded-For` et `X-Real-IP` DOIVENT valoir l'**IP réelle du client**
    (FR-02 : `CF-Connecting-IP` derrière Cloudflare), une seule adresse : tout
    `X-Forwarded-For` reçu est remplacé. `X-Forwarded-For` portait l'adresse du
    point de présence Cloudflare (`RemoteAddr`), et une origine configurée en
    `real_ip_header X-Forwarded-For` (README, `upstream.conf.example`)
    attribuait tout le trafic à quelques IP de Cloudflare
  - `X-Forwarded-Proto` DOIT valoir le schéma vu par le **client** : `https`
    quand le WAF termine le TLS, et derrière Cloudflare celui de l'en-tête
    `CF-Visitor` (`{"scheme":"https"}`), honoré seulement s'il vient d'une plage
    Cloudflare (ADR-019) ; `http` sinon. Il valait `http` pour un client en
    HTTPS derrière Cloudflare, et une origine qui redirige vers HTTPS bouclait
  - `X-Forwarded-Host` vaut le `Host` reçu
- Parmi les en-têtes internes `X-WAF-*`, seuls `X-WAF-Score` (score de confiance) et `X-WAF-Origin-Token` (FR-19) DOIVENT être transmis à l'upstream ; les en-têtes de coordination du pipeline (`X-WAF-Action`, `X-WAF-Reason`, `X-WAF-Risk-*`, `X-WAF-Global-Pressure`…) NE DOIVENT PAS l'être : aucun contrat ne les promet à l'application protégée, et ils exposaient la mécanique de décision du WAF
- Réciproquement, le WAF DOIT supprimer tout en-tête `X-WAF-*` d'une **réponse** de l'upstream : le pipeline lit ces en-têtes sur la réponse comme la décision du WAF (violation de circuit-breaker FR-08, action et raison journalisées et comptées FR-09). Transmis, un `X-WAF-Action: RATE_LIMIT` de l'origine comptait comme une violation, et un `X-WAF-Reason` quelconque devenait une série du label `reason`
- Le WAF DOIT supporter la configuration de plusieurs domaines avec upstreams distincts
- Le WAF DOIT supporter les WebSockets (upgrade HTTP)
- Le préfixe `/waf/` est **réservé** au WAF sur tous les domaines : aucune
  requête sous `/waf/` NE DOIT être transmise à l'upstream. Un chemin sous
  `/waf/` qui n'est pas un endpoint du WAF (`public.openapi.yaml`), ou un
  endpoint dont la fonction est désactivée (`/waf/verify` quand aucun hôte ne
  peut être challengé, `/waf/origin/verify` sans `origin_protection`), reçoit
  `404` du WAF. `/waf/stats` et `/waf/admin/*`, servis par la seule API
  d'administration, étaient transmis à l'origine depuis le listener public
- Le WAF DOIT pouvoir conserver l'en-tête `Host` entrant vers l'upstream (`upstream.preserve_host`) au lieu de le réécrire vers l'hôte de l'upstream — requis quand l'upstream route par `server_name` (ex: nginx/OpenResty en aval). Défaut : réécriture vers l'hôte upstream (comportement historique)

### FR-02 — Extraction IP Cloudflare
- Le WAF DOIT extraire l'IP réelle depuis le header `CF-Connecting-IP` quand la requête provient d'un IP Cloudflare connu
- Le WAF DOIT maintenir une liste des plages IP Cloudflare (IPv4 et IPv6)
- Le WAF DOIT rejeter les requêtes qui tentent de forger `CF-Connecting-IP` depuis des IPs non-Cloudflare
- Le WAF DEVRAIT mettre à jour automatiquement les plages IP Cloudflare (`cloudflare.auto_update_ranges`, désactivé par défaut) :
  - Sources : `https://www.cloudflare.com/ips-v4` et `https://www.cloudflare.com/ips-v6`, en HTTPS exclusivement
  - Un rafraîchissement DOIT avoir lieu au démarrage puis toutes les `cloudflare.update_interval`
  - La liste compilée dans le binaire sert de valeur initiale et de **repli permanent** : une liste récupérée n'est adoptée qu'entière et valide
  - Le WAF DOIT rejeter une liste récupérée qui élargirait la confiance au-delà du plausible — préfixe non canonique, préfixe plus large que `/8` (IPv4) ou `/19` (IPv6), famille d'adresses incohérente avec la source, nombre de préfixes hors bornes, corps de réponse surdimensionné. Sur rejet, la liste en vigueur est CONSERVÉE (jamais de liste vide, jamais d'élargissement silencieux)
  - Un échec de récupération NE DOIT PAS empêcher le WAF de démarrer ni de servir : il est journalisé et compté (`waf_cloudflare_ranges_update_total{result="error"}`)
  - Le WAF DOIT exposer le nombre de préfixes en vigueur (`waf_cloudflare_ranges`) et l'origine de la liste (compilée ou récupérée)
- `cloudflare.auto_update_ranges` sans `cloudflare.trusted` est une contradiction (les plages ne servent qu'à valider `CF-Connecting-IP`) et DOIT être rejeté au démarrage
- **Identité client.** Tout contrôle « par IP » (rate limit FR-03, trust score FR-04/FR-05, circuit-breaker FR-08, borne slowloris FR-23, auto-protection de `/waf/verify` et anti-brute-force de l'API admin FR-30, détecteurs et moteur de risque, `ip_hash` des cookies et tokens de challenge) DOIT compter une adresse **IPv6 par son préfixe /64** et une IPv4 par son adresse (une IPv4 mappée `::ffff:a.b.c.d` est une IPv4). Un /64 est la plus petite allocation d'un abonné : compté par adresse complète, il donnait 2⁶⁴ identités, et chaque contrôle par IP se contournait en changeant d'adresse. La whitelist et la blacklist restent évaluées sur l'adresse complète (leurs entrées CIDR couvrent un préfixe). L'IP journalisée et transmise à l'upstream (`X-Real-IP`) reste l'adresse complète

### FR-03 — Rate Limiting
- Le WAF DOIT implémenter un rate limiting par IP avec algorithme Token Bucket
- Les limites s'appliquent à toute IP, quel que soit le domaine ou la route
  - **Différé** (ADR-022) : limites propres à un domaine ou à un motif de route.
    La surcharge `domains[].rate_limit_override`, acceptée mais jamais appliquée,
    a été retirée et est refusée au démarrage ; une implémentation future passe
    par une nouvelle spec et réintroduit la clé comme ajout
- Le WAF DOIT retourner HTTP 429 avec header `Retry-After` quand la limite est atteinte
- Le WAF DOIT supporter des limites distinctes pour : req/seconde, req/minute, req/heure
  - Chaque fenêtre est un Token Bucket propre au couple (IP, fenêtre) : débit de recharge = limite ÷ durée de la fenêtre, capacité = la limite elle-même (`burst` ne s'applique qu'à la fenêtre seconde)
  - Une requête n'est admise que si les TROIS fenêtres actives disposent d'un jeton ; un refus par une fenêtre NE DOIT PAS consommer le jeton des autres
  - Le `Retry-After` renvoyé est le plus grand des délais des fenêtres qui refusent
  - Le `reason` journalisé DOIT identifier la fenêtre qui a refusé (`rate_limit_exceeded`, `rate_limit_exceeded_minute`, `rate_limit_exceeded_hour`) — sinon un opérateur ne peut pas savoir quelle limite règle son trafic
  - `requests_per_minute: 0` ou `requests_per_hour: 0` désactive la fenêtre correspondante ; `requests_per_hour` DOIT être >= `requests_per_minute` quand les deux sont actives
  - Le resserrement de pression globale (FR-08) s'applique au débit de recharge des trois fenêtres, et la neutralité du 429 de pression (pas de pénalité de score) est évaluée sur les trois
- Le WAF DOIT exclure les IPs en whitelist du rate limiting

### FR-04 — Whitelist / Blacklist
- Le WAF DOIT supporter une whitelist d'IPs et de CIDR (ex: `192.168.0.0/16`)
- Le WAF DOIT supporter une blacklist d'IPs et de CIDR
- Le WAF DOIT bloquer les IPs en blacklist avec HTTP 403
- Une IPv4 mappée en IPv6 (`::ffff:a.b.c.d`) DOIT être évaluée comme l'IPv4
  `a.b.c.d`, côté adresse cliente comme côté entrée de liste (une entrée
  `::ffff:198.51.100.0/120` vaut `198.51.100.0/24`) : sinon `::ffff:198.51.100.5`
  échappait à l'entrée `198.51.100.5` et au CIDR `198.51.100.0/24`, comme le
  prévoit déjà l'identité client (FR-02)
- Le WAF DOIT laisser passer les IPs en whitelist sans aucune vérification
- Le WAF DOIT supporter des whitelists de user-agents (pour bots légitimes)
- Le WAF DOIT permettre la modification des listes sans redémarrage (hot-reload)

### FR-05 — Score de confiance visiteur
- Le WAF DOIT maintenir un score de confiance [0..100] par visiteur (clé: hash IP)
- Score initial : 50 pour les nouveaux visiteurs
- Augmentations : challenge JS réussi (+25)
  - **Retiré** : « navigation normale (+1/req) », jamais implémenté. Il ferait
    croître la confiance avec le volume (un bot gagne +50 en 50 requêtes) et
    coûterait une écriture du store à chaque requête ; la confiance d'un humain
    vient du challenge réussi et des crédits de preuve humaine (FR-37)
- Diminutions : challenge JS échoué (-20), rate limit atteint (-10), user-agent suspect (-15), pattern bot (-30)
- La pénalité « rate limit atteint » DOIT être appliquée **au plus une fois par fenêtre de pénalité** (10 s) : les sous-requêtes refusées d'un même chargement de page (CSS, JS, images, appels API) comptent pour UNE pénalité, pas une par 429 — sinon un seul clic suffit à faire passer un humain de 50 à BLOCKED
- La pénalité « rate limit atteint » NE DOIT PAS s'appliquer à un 429 imputable au seul resserrement de pression globale (`rate_limit_pressure`, cf. FR-08) : la requête aurait été admise au débit nominal, le visiteur n'a rien fait d'anormal
- Seuils d'action configurables :
  - `challenge_threshold` (défaut: 40) — en dessous : challenge JS requis
  - `block_threshold` (défaut: 10) — en dessous : blocage HTTP 403
- Les scores DOIVENT expirer (TTL configurable, défaut: 1h)
- Toute modification de l'état d'un visiteur (score, glissement du TTL, circuit-breaker, preuve humaine, propagation cluster) DOIT être une lecture-calcul-écriture **atomique** vis-à-vis des autres écritures de ce visiteur, y compris depuis une autre instance sur un backend partagé (compare-and-set Redis, rejoué sur conflit). Une lecture suivie d'une écriture laissait la requête voisine effacer une pénalité : 50 pénalités concurrentes de −1 n'en retiraient qu'une partie

### FR-06 — Challenge JavaScript
- Le WAF DOIT servir une page HTML avec challenge JS aux visiteurs sous le seuil de confiance
- Le challenge JS DOIT inclure :
  - Un token unique signé (nonce + timestamp + IP hash) généré côté serveur
  - Un calcul proof-of-work (trouver N tel que SHA-256(nonce + N) commence par K zéros)
  - Un fingerprinting navigateur (user-agent, timezone, screen, langue, plugins, canvas hash, WebGL hash)
  - Un timer de durée : un plafond (`max_elapsed_ms`, défaut 60 s) au-delà duquel le challenge est considéré abandonné. La durée comparée au plancher et au plafond DOIT être **mesurée par le serveur**, de l'émission du token (horodatage signé à la milliseconde) à la soumission : l'`elapsed_ms` envoyé par le client, qu'il choisit librement, rendait le plancher décoratif. Il reste requis dans la soumission (contrat), à titre indicatif. Le plancher (`min_elapsed_ms`) est **désactivé par défaut** (0) car une PoW se résout en quelques dizaines de ms sur un client rapide et un plancher positif rejetait ces résolutions légitimes (`challenge_too_fast`). La résistance anti-bot repose sur la PoW + le fingerprint + le cookie, pas sur le chrono ; un opérateur peut réactiver un plancher (`min_elapsed_ms > 0`). Le token expire après `challenge.token_ttl` (30 s) : avec les défauts, il expire avant le plafond de 60 s, et une soumission tardive reçoit `token_expired` ; `challenge_timeout` n'est atteint qu'avec un `max_elapsed_ms` inférieur au `token_ttl`
- Le WAF DOIT valider la soumission du challenge via POST `/waf/verify`
- Le WAF DOIT émettre un cookie de session signé HMAC-SHA256 après validation
- Le token de challenge et le cookie de clearance DOIVENT être signés avec des **clés distinctes**, dérivées de `challenge.secret_key` par usage (HMAC-SHA256 du secret et d'une étiquette d'usage). Le token est remis à tout visiteur dans la page : signé avec la même clé et au même format que le cookie, il se validait comme clearance et, posé dans `waf_session`, franchissait le challenge sans PoW, mode « sous attaque » (FR-39) compris. Un token présenté comme cookie DOIT être refusé (le visiteur reçoit le challenge)
- Le WAF DOIT rediriger automatiquement vers l'URL originale après validation
- La page DOIT afficher le design fourni avec chronomètre et branding "Protected by GaetanDev.fr"
- Le WAF DOIT rejeter les challenges soumis après expiration (TTL: 30 s)
- Le WAF NE DOIT servir le challenge JS que pour une **navigation de navigateur** (méthode `GET`/`HEAD` avec `Accept` contenant `text/html`). Les appels API/XHR (`fetch`, `axios`, clients mobiles…) ne peuvent pas exécuter le JS : ils contournent le challenge (et restent couverts par le rate-limit, le moteur de risque, etc.) au lieu d'être cassés par une page HTML
- La page de challenge et les réponses de `/waf/verify` (succès comme erreur) DOIVENT être non-cacheables (`Cache-Control: no-store`, `Pragma: no-cache`, `Expires: 0`) : le token est court et lié à l'IP, un cache CDN figerait un token expiré pour tous les visiteurs → boucle de challenge infinie
- La page de challenge DOIT porter une `Content-Security-Policy` stricte à nonce,
  tirée à chaque réponse : `default-src 'none'; script-src 'nonce-…'; style-src
  'nonce-…'; connect-src 'self'; base-uri 'none'; form-action 'none';
  frame-ancestors 'none'`. Seuls son script et son style inline, marqués du nonce,
  s'exécutent ; la page ne joint que `/waf/verify`. Défense en profondeur de
  l'échappement contextuel (`html/template`) des valeurs injectées (token, URL de
  retour) : la page s'affiche sur tous les domaines protégés
- Le challenge JS DOIT être activable/désactivable **par domaine** via `domains[].challenge_enabled`, qui surcharge le `challenge.enabled` global :
  - clé **absente** → le domaine hérite de `challenge.enabled` (défaut : activé). Un domaine listé uniquement pour son `upstream` ou son certificat NE DOIT PAS perdre le challenge par effet de bord
  - `false` → aucune page de challenge n'est servie sur ce domaine, **y compris en mode « sous attaque » (FR-39)** : c'est une déclaration explicite de l'opérateur (typiquement une API dont les clients ne peuvent pas exécuter de JS). Le domaine reste couvert par le reste de la chaîne (blacklist, rate-limit, anti-bot, moteur de risque)
  - `true` → le challenge est servi sur ce domaine même si `challenge.enabled` est `false` globalement
  - La correspondance d'hôte DOIT suivre les mêmes règles que le routage `domains[]` : insensible à la casse, port ignoré, correspondance exacte ou wildcard `*.example.com` (qui couvre aussi l'apex `example.com`), **première entrée correspondante gagne**
  - `POST /waf/verify` reste servi par le WAF sur tous les domaines (chemin réservé `/waf/`), quel que soit `challenge_enabled` : un token est lié à l'hôte qui l'a émis

### FR-07 — Anti-Bot
- Le WAF DOIT analyser les headers HTTP pour détecter les bots (User-Agent vide, bot connus, headless browsers)
- Le WAF DOIT détecter les patterns de navigation anormaux (intervalle entre requêtes, ordre des ressources)
- Le WAF DOIT détecter les requêtes vers des URLs honeypot configurables
  - Une requête vers un honeypot DOIT recevoir HTTP 403 (`action=HONEYPOT`), et
    le visiteur DOIT rester **banni** (HTTP 403, `action=BLOCK`,
    `reason=honeypot_ban`, déclencheur déterministe `honeypot`) sur toutes ses
    requêtes suivantes, `/waf/verify` compris, pendant
    `trust.score_ttl`, assets statiques compris (FR-24), moteur de risque actif
    ou non, mode shadow compris. Le ban est un signal déterministe (FR-35) porté
    par l'état du visiteur (`honeypot_until`, `visitor.schema.json`) : le score
    remis à 0 ne bloquait que via le middleware de trust score, qui n'est pas
    monté quand le moteur de risque est actif — le ban ne durait qu'une requête.
    Seule la requête piège est journalisée `HONEYPOT` (et alertée, FR-29) : les
    requêtes bannies qui suivent sont des `BLOCK`, sans nouvelle alerte honeypot.
    Le ban est vérifié juste après la blacklist, avant le challenge : un
    visiteur banni ne reçoit pas de page de challenge
  - Par défaut, `honeypot_paths` ne contient que des chemins qu'aucune
    application ne sert à ses utilisateurs (`/.env`, `/wp-config.php`,
    `/.git/config`, `/phpinfo.php`) : `/admin.php`, page d'administration
    légitime de nombreuses applications PHP, en a été retiré
- Le WAF DOIT appliquer des règles basées sur la présence/absence de certains headers (Accept, Accept-Language, Accept-Encoding)
- Le WAF DOIT scorer négativement les user-agents de headless browsers (Headless Chrome, PhantomJS, Puppeteer-known signatures)
- Un User-Agent de `whitelist_user_agents` NE DOIT PAS être pénalisé par les heuristiques qui établissent seulement que le client n'est pas un navigateur (en-têtes `Accept-Language`/`Accept-Encoding` absents, UA d'outil) : un crawler légitime n'envoie pas ces en-têtes, et la pénalité répétée le bloquait avant la vérification reverse-DNS (`risk_engine.verified_bots`). Honeypot, UA d'automation et navigateurs headless RESTENT évalués
- En mode calibration (`risk_engine.shadow_mode`, moteur de risque actif), le WAF DOIT **observer** les blocages heuristiques de l'anti-bot (UA suspect, headers manquants…) sans les appliquer, afin de ne pas casser le trafic API/serveur légitime non-navigateur le temps de l'observation. Le honeypot, signal **déterministe** sans faux positif, RESTE bloquant même en shadow. Sans moteur de risque (`risk_engine.enabled: false`), `shadow_mode` est sans effet : l'anti-bot applique ses blocages (le défaut `shadow_mode: true` désactivait sinon tout blocage heuristique de l'anti-bot dans ce mode)

### FR-08 — Anti-DDoS
- Le WAF DOIT détecter une augmentation anormale du taux de requêtes par IP et par domaine
- Le WAF DOIT implémenter un circuit-breaker par IP : blocage temporaire après N violations consécutives
- Une violation est un refus du **rate limit du WAF** (`X-WAF-Action: RATE_LIMIT`). Un `429` venu de l'**upstream** (rate limit applicatif) NE DOIT PAS compter : le WAF transformerait sinon la limite d'une API en bannissement réseau de l'IP
- Le WAF DOIT supporter la configuration d'un seuil global de trafic (req/s total) servant de baseline de pression, sans blocage global automatique
- Le WAF DOIT calculer un niveau de pression global explicite : `normal`, `elevated`, `high`, `critical`
- Le WAF NE DOIT PAS retourner HTTP 503, HTTP 403 ou ouvrir un blocage complet uniquement parce que le seuil global de trafic est dépassé
- Le WAF DOIT utiliser la pression globale comme signal adaptatif pour renforcer les mitigations réversibles : contribution `rate`/`global_pressure`, challenge plus fréquent des visiteurs inconnus, difficulté PoW accrue, rate limit plus strict pour visiteurs inconnus ou suspects
  - Le « challenge plus fréquent » est le mode sous attaque (FR-39) : dès `antiddos.under_attack.trigger_pressure` (défaut `high`), toute requête sans clearance est challengée. Sous ce seuil, la pression n'agit sur le challenge qu'à travers la contribution `rate` du moteur de risque ; aucune autre règle ne challenge davantage
- Le resserrement du rate limit sous pression DOIT réduire uniquement le **débit de refill** (rate × facteur de pression) et conserver la **capacité de burst nominale** : un chargement de page unique (rafale de 25-50 sous-requêtes) DOIT passer même sous pression critique — c'est le débit soutenu qui distingue un bot, pas le burst initial
- Un 429 imputable au seul resserrement de pression (la requête aurait été admise au débit de refill nominal) DOIT être identifié `reason=rate_limit_pressure` et DOIT rester **neutre** : ni violation de circuit-breaker, ni pénalité de score de confiance (FR-05) — sans quoi le WAF ouvre le circuit et bloque des humains à cause des 429 qu'il a lui-même provoqués (boucle de rétroaction auto-infligée)
- Un 429 correspondant à un dépassement du débit nominal (`reason=rate_limit_exceeded`) DOIT continuer à compter comme violation de circuit-breaker et à pénaliser le score, y compris sous pression
- Le WAF DOIT laisser les visiteurs connus, les visiteurs avec cookie valide et les bots vérifiés continuer selon les contrôles par IP, blacklist explicite, circuit-breaker et moteur de risque
- Le WAF DOIT exposer le niveau de pression courant dans les logs et métriques afin de permettre l'alerte et la calibration

### FR-09 — Journalisation des événements de sécurité
- Le WAF DOIT journaliser chaque événement de sécurité (bloc, challenge, rate-limit) en JSON structuré
- L'`action` loggée DOIT refléter une décision RÉELLE du WAF (en-tête `X-WAF-Action` posé par un middleware) ; un statut provenant de l'**upstream** (ex: 502 origine indisponible, 403/404 applicatif) DOIT être loggé `action=PASS` avec son `upstream_status` réel — jamais comme un blocage WAF (sinon métriques `waf_blocked_total` faussées et fausses alertes webhook)
- Chaque log DOIT contenir : timestamp, request_id, ip, domain, path, action, reason, trust_score
- Une soumission rejetée par `POST /waf/verify` (400 : corps invalide, token invalide ou expiré, PoW faux, timing ou rendu WebGL headless refusé ; 405 : méthode autre que POST) est une décision du WAF : elle DOIT être journalisée et comptée `BLOCK`, avec la reason `verify_<code d'erreur>` (ex. `verify_invalid_pow`, `verify_token_expired`). Sans action posée, ces attaques du point de vérification étaient enregistrées `PASS`
- Les refus pris en amont de la chaîne de décision DOIVENT être journalisés et comptés comme toute décision du WAF : slowloris (`RATE_LIMIT`, `too_many_connections_per_ip`, FR-23), flood de `/waf/verify` (`RATE_LIMIT`, `self_protect_flood`, FR-30) et `server.strict_host` (`BLOCK`, `host_not_declared`, ADR-020). Montés au-dessus du journal et des métriques, ils étaient absents de `waf_requests_total`, du journal de sécurité et de `GET /waf/admin/events`
- Le WAF DOIT supporter les niveaux de log : debug, info, warn, error
- Le WAF DOIT supporter deux formats de sortie (`logging.format`), aux contrats explicitement distincts :
  - `json` (défaut, production) : une ligne JSON par événement, conforme à `security-event.schema.json` — c'est le **contrat d'audit**, seul format exploitable par un collecteur (Loki, Datadog) et seul format sur lequel porte la conformité de schéma
  - `pretty` (développement) : rendu console d'une ligne par événement, lisible par un humain, colorisé quand la sortie est un terminal. Ce format est **hors du contrat d'audit** : il promeut les champs utiles au diagnostic et omet les champs vides ou redondants. Il NE DOIT PAS être utilisé là où les logs sont collectés
  - La colorisation DOIT être désactivée quand la sortie n'est pas un terminal (redirection, pipe, fichier) ou quand `NO_COLOR` est défini — des séquences ANSI dans un fichier de log le rendent illisible
  - Le choix du format NE DOIT PAS changer le niveau, la destination, ni le caractère asynchrone de l'écriture
- L'écriture des logs NE DOIT PAS bloquer le traitement des requêtes : elle est asynchrone (tampon + écriture en arrière-plan). Si la sortie ralentit (rotation, disque, pipe non lu) et que le tampon est plein, les lignes sont abandonnées plutôt que de bloquer le chemin de requête (voir NFR-16) ; leur nombre DOIT être exposé par le compteur Prometheus `waf_log_events_dropped_total` (compté mais jamais publié jusque-là : des événements se perdaient sous flood sans trace)
- Le WAF DOIT exposer les métriques Prometheus sur `/waf/metrics`
- Les métriques DOIVENT inclure : req_total, req_blocked_total, req_challenged_total, req_latency_histogram
- Le label `domain` des métriques DOIT avoir une cardinalité bornée par la configuration : un hôte déclaré dans `domains[]` (casse ignorée, port retiré) porte son propre label, un hôte couvert par un wildcard porte le wildcard (`*.example.com`), tout autre hôte est compté sous `_undeclared`. Le `Host` est fourni par le client : en faire un label, c'est laisser un attaquant créer une série Prometheus par requête (mémoire non bornée)

### FR-10 — API Admin
- Le WAF DOIT exposer une API REST admin sur un port séparé (défaut: 9090)
- `GET /waf/health` de l'API admin (non authentifié) DOIT répondre `status: "degraded"` quand le backend Redis sert son état local (mode dégradé, ADR-021), `"ok"` sinon. Le `/waf/health` du listener public reste `"ok"` : il sonde le processus, pas le stockage
- L'API DOIT être protégée par un token Bearer
- L'API DOIT permettre : consulter/modifier config, gérer whitelist/blacklist, visualiser les visiteurs actifs, consulter les événements récents

---

## Non-Functional Requirements

### NFR-01 — Performance
- Latence ajoutée P50 < 1 ms pour visiteurs avec cookie valide
- Latence ajoutée P99 < 5 ms pour visiteurs avec cookie valide
- Débit cible : > 50 000 req/s sur un serveur 4 vCPU / 4 GB RAM
- Usage mémoire < 512 MB pour 100 000 visiteurs actifs en mémoire
- Temps de démarrage < 500 ms

### NFR-02 — Fiabilité
- Le WAF DOIT continuer à fonctionner en mode dégradé si l'upstream est indisponible (retourner 502 sans crash)
- Le WAF DOIT gérer le hot-reload de configuration sans interruption de trafic
- Goroutine leak : zéro fuite sur les goroutines de proxy

### NFR-03 — Sécurité
- Les cookies de session DOIVENT être signés HMAC-SHA256 avec une clé secrète
- Les tokens de challenge DOIVENT expirer après 30 secondes
- Les clés secrètes DOIVENT être configurables via variables d'environnement : `WAF_CHALLENGE_SECRET_KEY`, `WAF_ADMIN_TOKEN`, `WAF_ORIGIN_SECRET`, `WAF_REDIS_PASSWORD`, `WAF_ABUSEIPDB_KEY` et `WAF_ALERTING_WEBHOOKS_<i>_URL` (l'URL d'un webhook Slack ou Discord porte son jeton). La clé AbuseIPDB et les URL de webhook n'en avaient pas, et `WAF_ABUSEIPDB_KEY`, documentée, n'existait pas
- L'API admin DOIT être sur un port réseau distinct non exposé publiquement : `server.admin_listen` DOIT valoir par défaut `127.0.0.1:9090` (boucle locale). Le défaut `:9090` écoutait sur toutes les interfaces, en HTTP clair
- Aucune donnée PII dans les logs (pas d'URL complète avec query params sensibles en INFO)

### NFR-04 — Maintenabilité
- Code Go avec `gofmt` et `golangci-lint` sans erreur
- Couverture de tests > 80% sur le code business logic
- Zéro `panic` non récupéré dans les goroutines de traitement de requêtes : un
  `panic` d'un handler du listener public ou de l'API admin DOIT être récupéré
  par le WAF lui-même — journal `error` (`request_id`, méthode, chemin, pile),
  compteur Prometheus `waf_panics_total`, puis `500` si aucun en-tête de
  réponse n'est encore parti (texte brut sur le listener public, enveloppe
  `{"error": "internal_error"}` sur l'API admin), connexion interrompue sinon.
  `http.ErrAbortHandler` (abandon volontaire, ex. copie d'un corps upstream
  interrompue) n'est pas un incident et reste propagé. La récupération de
  `net/http` protégeait le processus, mais sans `request_id`, sans métrique, et
  en coupant la connexion sans réponse
- Documentation des interfaces publiques (godoc)
- Fichier de configuration validé au démarrage avec messages d'erreur clairs

### NFR-05 — Déploiement
- Binaire statique unique (CGO_ENABLED=0)
- Image Docker multi-stage < 30 MB
- Configuration via fichier YAML + variables d'environnement
- Compatible : Bare metal Linux, Docker, Docker Compose, Kubernetes (DaemonSet/Deployment)
- Signal SIGTERM géré pour graceful shutdown (drain des connexions actives)
  - Tous les serveurs démarrés (public, API admin, challenge ACME, redirection
    HTTPS) sont drainés **en parallèle**, chacun disposant du délai
    `server.graceful_shutdown_timeout` entier
  - L'échec d'un listener déclenche le même arrêt de tous les autres serveurs

### NFR-06 — Compatibilité
- Go 1.27+
- Linux AMD64 et ARM64
- IPv4 et IPv6 supportés partout
- TLS 1.2+ supporté côté upstream (vérification cert configurable)
