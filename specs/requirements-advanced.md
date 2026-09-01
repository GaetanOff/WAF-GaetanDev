---
status: implemented
version: 2.2.0
last-reviewed: 2026-09-01
reviewed-by: GaetanDev
extends: requirements.md (v2.0.0)
change: "FR-19 : la lecture du token retransmis par l'upstream sur `GET /waf/origin/verify` est explicitée comme l'exception documentée à l'assainissement d'ingress (FR-30)"
---

# Requirements Advanced — WAF Anti-DDoS / Anti-Bot (v2)

> Ce document étend `requirements.md` avec les fonctionnalités avancées.
> Les IDs FR-11 à FR-20 font suite aux FR-01 à FR-10 existants.

---

## FR-11 — TLS / JA3 Fingerprinting

- Le WAF DOIT calculer le hash JA3 du ClientHello TLS quand il termine lui-même le TLS (mode direct)
- Le WAF DOIT lire le header `Cf-Bot-Management-Ja3Hash` quand disponible (Cloudflare Bot Management)
- Le WAF DOIT maintenir une liste de hashes JA3 connus malveillants (configurable)
- Le WAF DOIT stocker le JA3 dans le `VisitorProfile` pour détection d'incohérence entre sessions
- Un hash JA3 en blacklist DOIT déclencher score -= 40 et un challenge immédiat
- Le WAF DEVRAIT détecter les changements de JA3 pour un même visiteur entre sessions (fingerprint swap = suspicieux)
- La collecte JA3 DOIT être optionnelle et désactivable (mode Cloudflare sans Bot Management)

## FR-12 — Behavioral Sequence Analysis

- Le WAF DOIT enregistrer les N dernières requêtes de chaque visiteur (path + timestamp) — configurable, défaut N=50
- Le WAF DOIT calculer en continu un **Behavioral Anomaly Score** (0=humain, 100=bot) basé sur :
  - **Uniformité temporelle** : écart-type des intervalles inter-requêtes < seuil → bot (humains ont des intervalles variables)
  - **Répétition de paths** : même path > K fois consécutives → crawler
  - **Vélocité de découverte** : > M paths uniques en < T secondes → crawler
  - **Ordre alphabétique** : séquence de paths triés → crawler systématique
  - **Absence de assets** : requêtes HTML sans requêtes CSS/JS/images associées → headless
  - **Profondeur de navigation** : visite directe de pages profondes sans passer par l'accueil → scraper
- Le Behavioral Anomaly Score DOIT influer sur le Trust Score global (anomaly > 70 → delta -20)
- Le WAF DOIT détecter le pattern "crawl burst" : période de requêtes intenses suivie de silence

## FR-13 — Intégration Threat Intelligence externe

- Le WAF DOIT supporter l'intégration avec **AbuseIPDB** (API v2) pour la réputation IP
  - Score AbuseIPDB ≥ 50 → Trust Score delta -20 ; ≥ 80 → delta -40
  - Cache des résultats avec TTL configurable (défaut 1h)
  - Quota API respecté (max 1000 req/jour gratuit)
- Le WAF DOIT maintenir une liste auto-mise-à-jour des **Tor exit nodes** (depuis https://check.torproject.org/torbulkexitlist)
  - IP Tor détectée → Trust Score delta -25
- Le WAF DOIT supporter une base de données **ASN** pour détecter les ranges datacenter/VPN/hosting
  - IPs dans des ASN connus (AWS, GCP, Azure, DigitalOcean, OVH, etc.) → Trust Score delta -10 (potentiellement bot)
  - Configurable : certains ASN peuvent être whitelistés (ex : Cloudflare lui-même)
- Le WAF DOIT supporter des **feeds YAML locaux** de threat intelligence (IP ranges, ASNs, domaines) avec rechargement automatique
- Le WAF DOIT exposer via l'API admin les statistiques de reputation lookups (hit rate, API calls, cache efficiency)

## FR-14 — Adaptive PoW Difficulty

- Le WAF DOIT ajuster dynamiquement la difficulté du PoW en fonction de l'intensité de l'attaque courante
- La difficulté DOIT être calculée par une fonction de l'indicateur d'attaque global :
  - **Niveau Normal** (trafic < 110% baseline) : difficulté = `challenge.pow_difficulty` (valeur config)
  - **Niveau Élevé** (trafic 110-200% baseline) : difficulté += 4 bits
  - **Niveau Critique** (trafic > 200% baseline) : difficulté += 8 bits (max configurable, défaut 24)
- La difficulté DOIT revenir progressivement au niveau normal après la fin de l'attaque (décroissance exponentielle sur 5 min)
- La difficulté courante DOIT être exposée dans les métriques Prometheus (`waf_challenge_pow_difficulty`)
- La page challenge DOIT adapter le message affiché selon la difficulté ("Vérification renforcée" si niveau critique)
- La difficulté DOIT être incluse dans le token de challenge (vérifiée côté serveur pour éviter la rétrogradation)

## FR-15 — Deception Layer (Tarpit + Honeypot Content)

### Tarpit
- Le WAF DOIT implémenter un mode **tarpit** : les requêtes identifiées comme bots reçoivent une réponse HTTP 200 intentionnellement lente (envoi des bytes par petits chunks avec délai configurable)
- Le tarpit DOIT être activable par règle (ex : user-agent bot connu, score < 15)
- Le tarpit ne DOIT PAS consommer des goroutines illimitées — limite configurable de connexions tarpitées simultanées
- Le WAF DOIT simuler une vraie réponse HTML pendant le tarpit (titre, structure) pour piéger les scrapers

### Honeypot Content Injection
- Le WAF DOIT être capable d'**injecter silencieusement** dans les réponses HTML proxifiées :
  - Des liens invisibles (CSS `display:none`) vers des URLs honeypot
  - Des adresses email factices (pour détecter les harvesters)
  - Des données de formulaire piégées (honeypot fields)
- Le WAF DOIT détecter quand un visiteur suit un lien honeypot injecté → score = 0 + blocage immédiat
- L'injection DOIT être opt-in par domaine (désactivée par défaut)
- L'injection DOIT se limiter aux réponses `Content-Type: text/html`

## FR-16 — Règles Géographiques

- Le WAF DOIT lire le header `CF-IPCountry` (fourni par Cloudflare, code ISO 3166-1 alpha-2)
- Le WAF DOIT supporter des règles par pays :
  - **Blocage total** : pays → HTTP 403
  - **Rate limit renforcé** : pays → `requests_per_second` réduit
  - **Challenge systématique** : pays → challenge toujours déclenché (override du score threshold)
  - **Score delta** : pays → Trust Score ajustement initial
- Le WAF DOIT supporter des **listes de pays autorisés** (whitelist — tous les autres → blocage)
- Les règles géographiques DOIVENT être configurables par domaine
- En l'absence du header CF-IPCountry (déploiement sans Cloudflare) → règles geo ignorées gracieusement

## FR-17 — Moteur de Règles Personnalisées (Rules Engine)

- Le WAF DOIT implémenter un moteur de règles basé sur un DSL YAML (cf. `schemas/rule.schema.json`)
- Chaque règle DOIT avoir : `name`, `priority`, `conditions[]`, `actions[]`, `enabled`
- **Conditions supportées** :
  - `ip` : equals, in_list, in_cidr, in_asn
  - `user_agent` : contains, matches_regex, equals
  - `path` : equals, starts_with, ends_with, matches_regex
  - `method` : equals, in_list
  - `header` : exists, equals, contains (header name + value)
  - `query_param` : exists, equals, matches_regex (param name + value)
  - `country` : equals, in_list
  - `trust_score` : lt, gt, lte, gte
  - `ja3_hash` : equals, in_list
  - `behavioral_score` : lt, gt
  - `hour_of_day` : between (pour règles temporelles)
- **Actions supportées** :
  - `block` : HTTP 403 avec message configurable
  - `challenge` : forcer le challenge JS
  - `score_delta` : modifier le trust score
  - `rate_limit` : appliquer une limite spécifique
  - `redirect` : redirection HTTP 301/302
  - `add_header` : ajouter un header à la réponse
  - `log` : forcer un log event avec niveau et message
  - `tarpit` : activer le tarpit
- Les règles DOIVENT être évaluées par ordre de priorité (plus petit = évalué en premier)
- Le premier match DOIT exécuter les actions (short-circuit configurable avec `continue: true`)
- Hot-reload sans redémarrage (SIGHUP ou API admin)
- Le WAF DOIT exposer via l'API admin : liste des règles, hit count par règle, last match timestamp

## FR-18 — Analyse d'Intégrité des Requêtes

- Le WAF DOIT normaliser les paths HTTP et détecter les tentatives d'obfuscation :
  - Path traversal : `../`, `%2e%2e`, `%2f`, double-encoding
  - Null bytes : `%00` dans le path ou query string
  - Excessive longueur : path > 2048 chars ou query string > 4096 chars
- Le WAF DOIT détecter les patterns d'injection dans les query parameters :
  - SQL keywords patterns (SELECT, UNION, DROP, etc.) dans les params
  - Script injection patterns (`<script>`, `javascript:`, `onerror=`)
  - Note : ces détections contribuent au score (delta -30) mais ne bloquent pas directement (laisser l'app décider)
- Le WAF DOIT valider le header `Content-Type` sur les requêtes POST/PUT/PATCH :
  - Mismatch entre Content-Type déclaré et body réel → log event
- Le WAF DOIT limiter la taille du body des requêtes (configurable, défaut 10 MB)

## FR-19 — Protection de l'Origine

- Le WAF DOIT injecter un **header secret** dans toutes les requêtes proxifiées vers l'upstream :
  `X-WAF-Origin-Token: <HMAC-SHA256(secret, domain + timestamp_hour)>`
- Le token DOIT être rotatif (change toutes les heures, tolérance 2h pour éviter les coupures)
- La valeur de ce header DOIT être configurable (`origin_protection.secret`)
- Le WAF DOIT exposer un endpoint de validation `GET /waf/origin/verify` pour que l'upstream vérifie le token
- L'endpoint de validation DOIT lire le token que l'upstream lui **retransmet** dans `X-WAF-Origin-Token`. C'est la seule lecture légitime d'un `X-WAF-*` d'origine cliente : elle constitue l'exception documentée à l'assainissement d'ingress (FR-30), et le token DOIT donc être capturé avant celui-ci. La valeur est vérifiée par HMAC, jamais honorée sur sa seule présence
- Les requêtes à l'upstream SANS ce header (bypass direct) POURRONT être rejetées côté upstream via middleware dédié
- Le WAF DEVRAIT supporter l'authentification mTLS vers l'upstream (cert client configurable)

## FR-20 — État Distribué Multi-Nœuds

- Le WAF DOIT supporter un mode **cluster** activable via config (`cluster.enabled: true`)
- En mode cluster, les événements suivants DOIVENT être partagés en temps réel via Redis Pub/Sub :
  - Nouvelles entrées blacklist (propagation < 1 s entre nœuds)
  - Ouverture de circuit-breaker pour une IP (tous les nœuds bloquent immédiatement)
  - Score de confiance d'un visiteur identifié comme très dangereux (score < 5)
  - Publication du niveau de pression global (coordination de l'attaque sans blocage global automatique)
- La propagation DOIT suivre un modèle **eventual consistency** (pas de transaction distribuée)
- En cas de perte de Redis, chaque nœud DOIT continuer à fonctionner de manière autonome (dégradé mais opérationnel)
- Le WAF DOIT exposer des métriques de synchronisation : `waf_cluster_sync_events_total`, `waf_cluster_lag_seconds`

---

## Non-Functional Requirements additionnels

### NFR-07 — Behavioral Analysis Performance
- L'analyse comportementale DOIT être exécutée de manière asynchrone (ne pas bloquer le pipeline de requêtes)
- Calcul du Behavioral Anomaly Score : exécuté sur un channel goroutine séparé, résultat appliqué à la requête suivante
- Overhead maximum de l'analyse comportementale : < 100 µs CPU par requête

### NFR-08 — Threat Intelligence Latence
- Les lookups de réputation IP DOIVENT être servis depuis le cache local (< 1 µs)
- Les lookups miss-cache DOIVENT être exécutés de manière asynchrone (non-bloquant pour la requête courante)
- Sur un miss cache, la décision de confiance DOIT utiliser le score de confiance existant (pas d'attente)

### NFR-09 — Rules Engine Performance
- Évaluation de 100 règles : < 500 µs par requête
- Compilation des règles au chargement (pas d'évaluation dynamique par requête)
- Hot-reload DOIT se faire en < 100 ms sans bloquer le trafic

### NFR-10 — Deception Layer Resource Control
- Le nombre de connexions tarpitées simultanées NE DOIT PAS dépasser `deception.tarpit_max_connections` (défaut: 500)
- Au-delà de la limite, les bots reçoivent un 429 plutôt qu'un tarpit (protection contre l'épuisement des goroutines)
