# Changelog — WAF Anti-DDoS / Anti-Bot

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

## [Unreleased]

### Changed

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
