---
status: implemented
version: 2.6.1
last-reviewed: 2026-09-25
reviewed-by: GaetanDev
extends: requirements.md (v2.0.0)
change: "FR-16 : avertissement au démarrage quand geo.challenge_countries est inerte faute de moteur de risque. Précédent (2.6.0) — FR-14 : anti-rétrogradation spécifiée en `invalid_pow`, plancher de pression précisé, message de page, métrique d'intensité et baseline 24 h marqués différés. Précédent (2.5.5) — FR-13 : paliers AbuseIPDB réalignés sur le vérificateur (≥ 80 déclencheur threat_intel_critical, ≥ 50 trust score plafonné à 20), plages locales et échec de source spécifiés. Précédent (2.5.4) — FR-16 : exigences réalignées sur le bloc `geo` implémenté, rate limit et score par pays, règles par domaine et métriques par pays marqués différés. Précédent (2.5.3) — FR-11 : sans moteur de risque, le middleware de trust score applique le déclencheur `ja3_blacklist` (403) — la blacklist JA3 était sans effet. Précédent (2.5.2) — FR-11 : un JA3 blacklisté est un déclencheur déterministe (BLOCK par le moteur de risque, FR-35), la clause « score -= 40 et challenge immédiat » antérieure au moteur est retirée. Précédent (2.5.1) — FR-19 : le domaine signé est l'hôte normalisé (minuscules, port retiré). Précédent (2.5.0) — FR-12/FR-13 : profils comportementaux et entrées de réputation détaillés marqués différés (schémas draft). FR-17 : conditions et actions réalignées sur le moteur implémenté (rule.schema.json v2.0.0), chargement fail-fast, capacités non implémentées marquées différées. Précédent (2.4.0) — FR-16 : un `CF-IPCountry` non prouvé Cloudflare est supprimé à l'entrée (ADR-019 option B). Précédent (2.3.0) — FR-17 : la condition `ip` DOIT être évaluée sur l'IP réelle établie par le WAF, jamais sur un en-tête client — un `X-Real-IP` forgé contournait toute règle de blocage par IP (FR-19 v2.2.0 : lecture du token retransmis sur `GET /waf/origin/verify`)"
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
- Un hash JA3 en blacklist DOIT être déclaré **déclencheur déterministe** `ja3_blacklist` (requirements-detection FR-35, ADR-015) : le moteur de risque le bloque (HTTP 403) sans exigence de corroboration, et la raison journalisée est `ja3_blacklisted`. Aucun delta de trust score n'est appliqué. Cette clause remplace « score -= 40 et challenge immédiat », antérieure au moteur de risque
- En `risk_engine.shadow_mode`, la décision BLOCK du moteur est journalisée sans être appliquée. Sans moteur (`risk_engine.enabled: false`), le middleware de trust score applique lui-même le déclencheur (HTTP 403) : une blacklist JA3 configurée n'est jamais sans effet
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
- **Différé** (non implémenté) : signaux « profondeur de navigation » et « crawl
  burst » ; exposition du profil détaillé décrit par
  `schemas/behavioral-profile.schema.json` (statut draft) — le détecteur ne
  publie aujourd'hui qu'un score, consommé par le moteur de risque

## FR-13 — Intégration Threat Intelligence externe

- Le WAF DOIT supporter l'intégration avec **AbuseIPDB** (API v2) pour la réputation IP
  - Score AbuseIPDB ≥ 80 → verdict **critique** : déclencheur déterministe
    `threat_intel_critical`, BLOCK sans corroboration (FR-35) ; ≥ 50 → verdict
    **malveillant** : trust score plafonné à 20 ; en dessous, aucun effet. Cette
    clause remplace « delta -40 / -20 », antérieure au moteur de risque
  - Plages locales `blocklist_cidrs` (malveillant, plafond 20) et `suspect_cidrs`
    (suspect, plafond 35)
  - Une erreur ou un timeout de l'API vaut verdict « propre » : le WAF ne bloque
    jamais sur l'indisponibilité d'une source
  - Cache des résultats avec TTL configurable (défaut 1h)
  - Quota API respecté (max 1000 req/jour gratuit)
- Le WAF DOIT maintenir une liste auto-mise-à-jour des **Tor exit nodes** (depuis https://check.torproject.org/torbulkexitlist)
  - IP Tor détectée → Trust Score delta -25
- Le WAF DOIT supporter une base de données **ASN** pour détecter les ranges datacenter/VPN/hosting
  - IPs dans des ASN connus (AWS, GCP, Azure, DigitalOcean, OVH, etc.) → Trust Score delta -10 (potentiellement bot)
  - Configurable : certains ASN peuvent être whitelistés (ex : Cloudflare lui-même)
- Le WAF DOIT supporter des **feeds YAML locaux** de threat intelligence (IP ranges, ASNs, domaines) avec rechargement automatique
- Le WAF DOIT exposer via l'API admin les statistiques de reputation lookups (hit rate, API calls, cache efficiency)
- **Différé** (non implémenté) : liste Tor auto-mise-à-jour et base ASN (des
  plages Tor ou datacenter ne sont prises en compte que saisies en CIDR
  statiques, `threat_intel.blocklist_cidrs` / `suspect_cidrs`), feeds YAML
  rechargeables, statistiques admin, et entrées de réputation au format
  `schemas/threat-intel-entry.schema.json` (statut draft) — le vérificateur ne
  retient aujourd'hui qu'un verdict {niveau, raison} par IP, issu des CIDR
  configurés et d'AbuseIPDB ; métrique `waf_threat_intel_errors_total` et
  endpoint `GET /waf/admin/threat-intel/stats` (`threat-intelligence.feature`,
  scénarios `@deferred`)

## FR-14 — Adaptive PoW Difficulty

- Le WAF DOIT ajuster dynamiquement la difficulté du PoW en fonction de l'intensité de l'attaque courante
- La difficulté DOIT être calculée par une fonction de l'indicateur d'attaque global :
  - **Niveau Normal** (trafic < 110% baseline) : difficulté = `challenge.pow_difficulty` (valeur config)
  - **Niveau Élevé** (trafic 110-200% baseline) : difficulté += 4 bits
  - **Niveau Critique** (trafic > 200% baseline) : difficulté += 8 bits (max configurable, défaut 24)
- La difficulté DOIT revenir progressivement au niveau normal après la fin de l'attaque (décroissance exponentielle sur 5 min)
- La difficulté courante DOIT être exposée dans les métriques Prometheus (`waf_challenge_pow_difficulty`)
- La difficulté DOIT être incluse dans le token de challenge (vérifiée côté serveur pour éviter la rétrogradation) : un PoW qui ne satisfait pas la difficulté signée est refusé en `400 invalid_pow` (score -20), sans code d'erreur distinct
- La pression globale anti-DDoS (FR-08) impose un plancher immédiat : `elevated` +4, `high` +6, `critical` +8 bits
- **Différé** (non implémenté — `adaptive-protection.feature`, scénarios `@deferred`) : message de la page de challenge adapté à la difficulté (« Vérification renforcée »), métrique `waf_attack_intensity_indicator`, baseline EMA sur 24 h (la baseline est une EMA à α = 0,05 par calcul de difficulté, initialisée au premier débit observé) et repli sur `rate_limit.requests_per_second` au démarrage

## FR-15 — Deception Layer (Tarpit + Honeypot Content)

### Tarpit
- Le WAF DOIT implémenter un mode **tarpit** : les requêtes identifiées comme bots reçoivent une réponse HTTP 200 intentionnellement lente (envoi des bytes par petits chunks avec délai configurable)
- Le tarpit DOIT être activable par règle (ex : user-agent bot connu, score < 15)
- Le tarpit ne DOIT PAS consommer des goroutines illimitées — limite configurable de connexions tarpitées simultanées
- Le WAF DOIT simuler une vraie réponse HTML pendant le tarpit (titre, structure) pour piéger les scrapers
- Une réponse servie par le tarpit DOIT être journalisée et comptée avec l'action `TARPIT` (journal de sécurité, `waf_requests_total{action="TARPIT"}`, `GET /waf/admin/events`, `requests_tarpitted` de `GET /waf/stats`). Posée sur la requête, la classification `TARPIT` n'est pas une action : sans couche de déception, la requête atteint l'upstream et reste `PASS`
- Le 429 servi quand la limite de connexions tarpitées est atteinte DOIT être journalisé et compté `TARPIT` avec la reason `tarpit_saturated` : la requête n'atteint pas l'origine

### Honeypot Content Injection

> **Différé** (non implémenté — `deception-layer.feature`, scénarios
> `@deferred`) : toute cette sous-section. Les chemins piégés sont détectés par
> `honeypot_paths` (FR-07) ; aucune injection dans les réponses n'a lieu.

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
- Un `CF-IPCountry` reçu d'une connexion hors plage Cloudflare, ou avec `cloudflare.trusted: false`, est supprimé à l'entrée et traité comme absent (FR-30, ADR-019 option B)
- **Implémenté** (bloc `geo` de `config.schema.json`) : `blocked_countries` → 403
  `geo_country_blocked` ; `allowed_countries` → 403 `geo_country_not_allowed`
  pour tout autre pays ; `challenge_countries` → contribution
  `challenge_contribution` (défaut 60) de la famille `geo` au moteur de risque
  (FR-33), sans effet quand le moteur est désactivé — le démarrage le signale
  alors par un avertissement (`geo.challenge_countries has no effect while
  risk_engine.enabled is false`)
- **Différé** (non implémenté — `geo-rules.feature`, scénarios `@deferred`) :
  rate limit renforcé par pays, delta de score initial par pays, règles geo par
  domaine, label `country` des métriques et journal debug d'un code inconnu

## FR-17 — Moteur de Règles Personnalisées (Rules Engine)

- Le WAF DOIT implémenter un moteur de règles basé sur un DSL YAML (cf. `schemas/rule.schema.json`)
- Chaque règle DOIT avoir : `name`, `priority`, `conditions[]`, `actions[]`, `enabled`
- Les conditions d'une règle sont une **liste combinée en ET** ; il n'y a pas de
  groupe booléen. Le contrat exact est `schemas/rule.schema.json` v2.0.0
- **Conditions supportées** (valeurs sensibles à la casse) :
  - `ip` : equals, in_list, in_cidr
  - `user_agent`, `path`, `method`, `country`, `header` (clé `name`),
    `query_param` (clé `name`) : equals, contains, starts_with, ends_with,
    exists, in_list, matches_regex
  - `trust_score` : lt, lte, gt, gte (condition fausse tant que le score n'est
    pas connu)
- **Actions supportées** :
  - `block` : HTTP 403, raison configurable (`value`)
  - `tarpit` : classer la requête TARPIT (FR-15)
  - `score_delta` : modifier le trust score (`delta`)
  - `add_header` : ajouter un header à la réponse (`header`, obligatoire et nom d'en-tête HTTP valide ; `value`)
  - `log` : poser la raison journalisée (`value`)
- Le chargement DOIT échouer (fail-fast) sur un champ, un opérateur ou une
  action non supportés, sur une règle sans action, sur un `add_header` sans
  nom d'en-tête valide, et sur toute clé YAML
  inconnue : une règle partiellement comprise ne DOIT jamais être chargée
- **Différé** (spécifié, non implémenté — `rules-engine.feature`, scénarios
  `@deferred`) : groupes OR/NOT ; conditions `in_asn`, `ja3_hash`,
  `behavioral_score`, `hour_of_day` ; actions `challenge`, `rate_limit`,
  `redirect`, `allow` ; statut et message configurables du `block`
- La condition `ip` DOIT être évaluée sur l'**IP réelle établie par le WAF**
  (`CF-Connecting-IP` validée contre les plages Cloudflare quand
  `cloudflare.trusted`, sinon l'adresse de la connexion), et jamais sur un
  en-tête fourni par le client tel que `X-Real-IP` ou `X-Forwarded-For`
  - Motif : ces en-têtes traversent Cloudflare sans être réécrits. Une règle
    `ip in_cidr` de blocage serait contournée par un simple `X-Real-IP:
    8.8.8.8`, et une règle d'allocation de confiance par IP serait usurpable
  - Le WAF NE DOIT PAS non plus dériver l'IP de règle d'un en-tête qu'il pose
    lui-même vers l'upstream : `X-Real-IP` est un en-tête **sortant** (FR-01),
    sa présence en entrée n'a aucune signification
- Les règles DOIVENT être évaluées par ordre de priorité (plus petit = évalué en premier)
- Le premier match DOIT exécuter les actions (short-circuit configurable avec `continue: true`)
- **Différé** : hot-reload sans redémarrage (SIGHUP ou API admin) — les règles
  sont lues au démarrage ; `RuleSet.Load` est déjà un échange atomique
- **Différé** : exposition via l'API admin de la liste des règles, du hit count
  par règle et du last match timestamp (`GET/PATCH /waf/admin/rules`)

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
- `domain` est l'hôte **normalisé** (minuscules, port retiré), comme pour le routage `domains[]` : un Host `Example.com:443` est signé et vérifié comme `example.com`. Signé sur le Host brut, le token injecté échouait à `GET /waf/origin/verify?domain=example.com`
- Le token DOIT être rotatif (change toutes les heures, tolérance 2h pour éviter les coupures)
- La valeur de ce header DOIT être configurable (`origin_protection.secret`)
- **Différé** : rotation du secret sans interruption (acceptation d'un secret
  précédent pendant une fenêtre) — le secret est lu au démarrage, un
  changement exige un redémarrage
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
