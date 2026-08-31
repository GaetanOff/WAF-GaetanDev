---
status: approved
version: 2.2.0
last-reviewed: 2026-08-31
reviewed-by: GaetanDev
change: "FR-06 : `domains[].challenge_enabled` devient une surcharge à trois états (absent = hérite du global, false = jamais de challenge même sous attaque, true = force le challenge)"
---

# Requirements — WAF Anti-DDoS / Anti-Bot

## Functional Requirements

### FR-01 — Reverse Proxy
- Le WAF DOIT agir comme reverse proxy HTTP/1.1 et HTTP/2
- Le WAF DOIT transmettre les requêtes légitimes vers l'upstream configuré
- Le WAF DOIT préserver tous les headers originaux et ajouter `X-Forwarded-For`, `X-Real-IP`
- Le WAF DOIT supporter la configuration de plusieurs domaines avec upstreams distincts
- Le WAF DOIT supporter les WebSockets (upgrade HTTP)
- Le WAF DOIT pouvoir conserver l'en-tête `Host` entrant vers l'upstream (`upstream.preserve_host`) au lieu de le réécrire vers l'hôte de l'upstream — requis quand l'upstream route par `server_name` (ex: nginx/OpenResty en aval). Défaut : réécriture vers l'hôte upstream (comportement historique)

### FR-02 — Extraction IP Cloudflare
- Le WAF DOIT extraire l'IP réelle depuis le header `CF-Connecting-IP` quand la requête provient d'un IP Cloudflare connu
- Le WAF DOIT maintenir une liste des plages IP Cloudflare (IPv4 et IPv6)
- Le WAF DOIT rejeter les requêtes qui tentent de forger `CF-Connecting-IP` depuis des IPs non-Cloudflare
- Le WAF DEVRAIT mettre à jour automatiquement les plages IP Cloudflare (configurable)

### FR-03 — Rate Limiting
- Le WAF DOIT implémenter un rate limiting par IP avec algorithme Token Bucket
- Le WAF DOIT supporter des limites configurables par domaine et par route pattern
- Le WAF DOIT retourner HTTP 429 avec header `Retry-After` quand la limite est atteinte
- Le WAF DOIT supporter des limites distinctes pour : req/seconde, req/minute, req/heure
- Le WAF DOIT exclure les IPs en whitelist du rate limiting

### FR-04 — Whitelist / Blacklist
- Le WAF DOIT supporter une whitelist d'IPs et de CIDR (ex: `192.168.0.0/16`)
- Le WAF DOIT supporter une blacklist d'IPs et de CIDR
- Le WAF DOIT bloquer les IPs en blacklist avec HTTP 403
- Le WAF DOIT laisser passer les IPs en whitelist sans aucune vérification
- Le WAF DOIT supporter des whitelists de user-agents (pour bots légitimes)
- Le WAF DOIT permettre la modification des listes sans redémarrage (hot-reload)

### FR-05 — Score de confiance visiteur
- Le WAF DOIT maintenir un score de confiance [0..100] par visiteur (clé: hash IP)
- Score initial : 50 pour les nouveaux visiteurs
- Augmentations : challenge JS réussi (+25), navigation normale (+1/req)
- Diminutions : challenge JS échoué (-20), rate limit atteint (-10), user-agent suspect (-15), pattern bot (-30)
- La pénalité « rate limit atteint » DOIT être appliquée **au plus une fois par fenêtre de pénalité** (10 s) : les sous-requêtes refusées d'un même chargement de page (CSS, JS, images, appels API) comptent pour UNE pénalité, pas une par 429 — sinon un seul clic suffit à faire passer un humain de 50 à BLOCKED
- La pénalité « rate limit atteint » NE DOIT PAS s'appliquer à un 429 imputable au seul resserrement de pression globale (`rate_limit_pressure`, cf. FR-08) : la requête aurait été admise au débit nominal, le visiteur n'a rien fait d'anormal
- Seuils d'action configurables :
  - `challenge_threshold` (défaut: 40) — en dessous : challenge JS requis
  - `block_threshold` (défaut: 10) — en dessous : blocage HTTP 403
- Les scores DOIVENT expirer (TTL configurable, défaut: 1h)

### FR-06 — Challenge JavaScript
- Le WAF DOIT servir une page HTML avec challenge JS aux visiteurs sous le seuil de confiance
- Le challenge JS DOIT inclure :
  - Un token unique signé (nonce + timestamp + IP hash) généré côté serveur
  - Un calcul proof-of-work (trouver N tel que SHA-256(nonce + N) commence par K zéros)
  - Un fingerprinting navigateur (user-agent, timezone, screen, langue, plugins, canvas hash, WebGL hash)
  - Un timer de durée : un plafond (`max_elapsed_ms`, défaut 60 s) au-delà duquel le challenge est considéré abandonné. Le plancher (`min_elapsed_ms`) est **désactivé par défaut** (0) car une PoW se résout en quelques dizaines de ms sur un client rapide et un plancher positif rejetait ces résolutions légitimes (`challenge_too_fast`). La résistance anti-bot repose sur la PoW + le fingerprint + le cookie, pas sur le chrono ; un opérateur peut réactiver un plancher (`min_elapsed_ms > 0`)
- Le WAF DOIT valider la soumission du challenge via POST `/waf/verify`
- Le WAF DOIT émettre un cookie de session signé HMAC-SHA256 après validation
- Le WAF DOIT rediriger automatiquement vers l'URL originale après validation
- La page DOIT afficher le design fourni avec chronomètre et branding "Protected by GaetanDev.fr"
- Le WAF DOIT rejeter les challenges soumis après expiration (TTL: 30 s)
- Le WAF NE DOIT servir le challenge JS que pour une **navigation de navigateur** (méthode `GET`/`HEAD` avec `Accept` contenant `text/html`). Les appels API/XHR (`fetch`, `axios`, clients mobiles…) ne peuvent pas exécuter le JS : ils contournent le challenge (et restent couverts par le rate-limit, le moteur de risque, etc.) au lieu d'être cassés par une page HTML
- La page de challenge et les réponses de `/waf/verify` (succès comme erreur) DOIVENT être non-cacheables (`Cache-Control: no-store`, `Pragma: no-cache`, `Expires: 0`) : le token est court et lié à l'IP, un cache CDN figerait un token expiré pour tous les visiteurs → boucle de challenge infinie
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
- Le WAF DOIT appliquer des règles basées sur la présence/absence de certains headers (Accept, Accept-Language, Accept-Encoding)
- Le WAF DOIT scorer négativement les user-agents de headless browsers (Headless Chrome, PhantomJS, Puppeteer-known signatures)
- En mode calibration (`risk_engine.shadow_mode`), le WAF DOIT **observer** les blocages heuristiques de l'anti-bot (UA suspect, headers manquants…) sans les appliquer, afin de ne pas casser le trafic API/serveur légitime non-navigateur le temps de l'observation. Le honeypot, signal **déterministe** sans faux positif, RESTE bloquant même en shadow

### FR-08 — Anti-DDoS
- Le WAF DOIT détecter une augmentation anormale du taux de requêtes par IP et par domaine
- Le WAF DOIT implémenter un circuit-breaker par IP : blocage temporaire après N violations consécutives
- Le WAF DOIT supporter la configuration d'un seuil global de trafic (req/s total) servant de baseline de pression, sans blocage global automatique
- Le WAF DOIT calculer un niveau de pression global explicite : `normal`, `elevated`, `high`, `critical`
- Le WAF NE DOIT PAS retourner HTTP 503, HTTP 403 ou ouvrir un blocage complet uniquement parce que le seuil global de trafic est dépassé
- Le WAF DOIT utiliser la pression globale comme signal adaptatif pour renforcer les mitigations réversibles : contribution `rate`/`global_pressure`, challenge plus fréquent des visiteurs inconnus, difficulté PoW accrue, rate limit plus strict pour visiteurs inconnus ou suspects
- Le resserrement du rate limit sous pression DOIT réduire uniquement le **débit de refill** (rate × facteur de pression) et conserver la **capacité de burst nominale** : un chargement de page unique (rafale de 25-50 sous-requêtes) DOIT passer même sous pression critique — c'est le débit soutenu qui distingue un bot, pas le burst initial
- Un 429 imputable au seul resserrement de pression (la requête aurait été admise au débit de refill nominal) DOIT être identifié `reason=rate_limit_pressure` et DOIT rester **neutre** : ni violation de circuit-breaker, ni pénalité de score de confiance (FR-05) — sans quoi le WAF ouvre le circuit et bloque des humains à cause des 429 qu'il a lui-même provoqués (boucle de rétroaction auto-infligée)
- Un 429 correspondant à un dépassement du débit nominal (`reason=rate_limit_exceeded`) DOIT continuer à compter comme violation de circuit-breaker et à pénaliser le score, y compris sous pression
- Le WAF DOIT laisser les visiteurs connus, les visiteurs avec cookie valide et les bots vérifiés continuer selon les contrôles par IP, blacklist explicite, circuit-breaker et moteur de risque
- Le WAF DOIT exposer le niveau de pression courant dans les logs et métriques afin de permettre l'alerte et la calibration

### FR-09 — Journalisation des événements de sécurité
- Le WAF DOIT journaliser chaque événement de sécurité (bloc, challenge, rate-limit) en JSON structuré
- L'`action` loggée DOIT refléter une décision RÉELLE du WAF (en-tête `X-WAF-Action` posé par un middleware) ; un statut provenant de l'**upstream** (ex: 502 origine indisponible, 403/404 applicatif) DOIT être loggé `action=PASS` avec son `upstream_status` réel — jamais comme un blocage WAF (sinon métriques `waf_blocked_total` faussées et fausses alertes webhook)
- Chaque log DOIT contenir : timestamp, request_id, ip, domain, path, action, reason, trust_score
- Le WAF DOIT supporter les niveaux de log : debug, info, warn, error
- L'écriture des logs NE DOIT PAS bloquer le traitement des requêtes : elle est asynchrone (tampon + écriture en arrière-plan). Si la sortie ralentit (rotation, disque, pipe non lu) et que le tampon est plein, les lignes sont abandonnées (compteur exposé) plutôt que de bloquer le chemin de requête (voir NFR-16)
- Le WAF DOIT exposer les métriques Prometheus sur `/waf/metrics`
- Les métriques DOIVENT inclure : req_total, req_blocked_total, req_challenged_total, req_latency_histogram

### FR-10 — API Admin
- Le WAF DOIT exposer une API REST admin sur un port séparé (défaut: 9090)
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
- Les clés secrètes DOIVENT être configurables via variables d'environnement
- L'API admin DOIT être sur un port réseau distinct non exposé publiquement
- Aucune donnée PII dans les logs (pas d'URL complète avec query params sensibles en INFO)

### NFR-04 — Maintenabilité
- Code Go avec `gofmt` et `golangci-lint` sans erreur
- Couverture de tests > 80% sur le code business logic
- Zéro `panic` non récupéré dans les goroutines de traitement de requêtes
- Documentation des interfaces publiques (godoc)
- Fichier de configuration validé au démarrage avec messages d'erreur clairs

### NFR-05 — Déploiement
- Binaire statique unique (CGO_ENABLED=0)
- Image Docker multi-stage < 30 MB
- Configuration via fichier YAML + variables d'environnement
- Compatible : Bare metal Linux, Docker, Docker Compose, Kubernetes (DaemonSet/Deployment)
- Signal SIGTERM géré pour graceful shutdown (drain des connexions actives)

### NFR-06 — Compatibilité
- Go 1.27+
- Linux AMD64 et ARM64
- IPv4 et IPv6 supportés partout
- TLS 1.2+ supporté côté upstream (vérification cert configurable)
