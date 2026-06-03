---
status: approved
version: 1.0.0
last-reviewed: 2026-06-03
---

# Requirements — WAF Anti-DDoS / Anti-Bot

## Functional Requirements

### FR-01 — Reverse Proxy
- Le WAF DOIT agir comme reverse proxy HTTP/1.1 et HTTP/2
- Le WAF DOIT transmettre les requêtes légitimes vers l'upstream configuré
- Le WAF DOIT préserver tous les headers originaux et ajouter `X-Forwarded-For`, `X-Real-IP`
- Le WAF DOIT supporter la configuration de plusieurs domaines avec upstreams distincts
- Le WAF DOIT supporter les WebSockets (upgrade HTTP)

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
  - Un timer de durée (doit prendre entre 500 ms et 10 s, sinon suspect)
- Le WAF DOIT valider la soumission du challenge via POST `/waf/verify`
- Le WAF DOIT émettre un cookie de session signé HMAC-SHA256 après validation
- Le WAF DOIT rediriger automatiquement vers l'URL originale après validation
- La page DOIT afficher le design fourni avec chronomètre et branding "Protected by GaetanDev.fr"
- Le WAF DOIT rejeter les challenges soumis après expiration (TTL: 30 s)

### FR-07 — Anti-Bot
- Le WAF DOIT analyser les headers HTTP pour détecter les bots (User-Agent vide, bot connus, headless browsers)
- Le WAF DOIT détecter les patterns de navigation anormaux (intervalle entre requêtes, ordre des ressources)
- Le WAF DOIT détecter les requêtes vers des URLs honeypot configurables
- Le WAF DOIT appliquer des règles basées sur la présence/absence de certains headers (Accept, Accept-Language, Accept-Encoding)
- Le WAF DOIT scorer négativement les user-agents de headless browsers (Headless Chrome, PhantomJS, Puppeteer-known signatures)

### FR-08 — Anti-DDoS
- Le WAF DOIT détecter une augmentation anormale du taux de requêtes par IP et par domaine
- Le WAF DOIT implémenter un circuit-breaker par IP : blocage temporaire après N violations consécutives
- Le WAF DOIT supporter la configuration d'un seuil global de trafic (req/s total) avec réponse dégradée
- Le WAF DOIT implémenter un slow-down progressif (503 avec Retry-After croissant) avant le blocage complet

### FR-09 — Journalisation des événements de sécurité
- Le WAF DOIT journaliser chaque événement de sécurité (bloc, challenge, rate-limit) en JSON structuré
- Chaque log DOIT contenir : timestamp, request_id, ip, domain, path, action, reason, trust_score
- Le WAF DOIT supporter les niveaux de log : debug, info, warn, error
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
- Go 1.22+
- Linux AMD64 et ARM64
- IPv4 et IPv6 supportés partout
- TLS 1.2+ supporté côté upstream (vérification cert configurable)
