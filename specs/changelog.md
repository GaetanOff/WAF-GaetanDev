# Changelog — WAF Anti-DDoS / Anti-Bot

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

## [Unreleased]

### Planned for v0.1.0
- Reverse proxy Go de base avec routing par domaine
- Extraction IP Cloudflare (CF-Connecting-IP)
- Whitelist / Blacklist IP et CIDR
- Rate limiting Token Bucket par IP
- Configuration YAML avec validation au démarrage

### Planned for v0.2.0
- Score de confiance par visiteur
- Challenge JavaScript (PoW + fingerprinting)
- Cookie de session signé HMAC-SHA256
- Détection bot (user-agent, headers manquants, honeypot)

### Planned for v0.3.0
- Circuit-breaker par IP
- Mode dégradé global (seuil trafic)
- Métriques Prometheus
- API Admin REST (:9090)

### Planned for v1.0.0
- Tests de conformance complets (tous les scénarios Gherkin)
- Docker multi-stage < 30 MB
- Documentation complète
- Release production-ready
