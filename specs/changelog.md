# Changelog — WAF Anti-DDoS / Anti-Bot

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

## [Unreleased]

Spécifications rédigées et approuvées, implémentation à venir (voir
`specs/requirements-advanced.md` et `specs/requirements-ops.md`) :

- TLS/JA3 fingerprinting, analyse comportementale, threat intelligence
- Difficulté de PoW adaptative, couche de déception (tarpit + honeypot)
- Moteur de règles YAML, règles géographiques, intégrité de requête
- Protection de l'origine, synchronisation multi-nœuds (Redis)
- En-têtes de sécurité, protection Slowloris, bypass des assets statiques
- Health checks upstream + load balancing, audit trail, conformité RGPD
- Webhooks d'alerte, auto-protection du WAF, ACME/Let's Encrypt

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
