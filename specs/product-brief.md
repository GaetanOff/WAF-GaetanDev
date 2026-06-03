---
status: approved
version: 1.0.0
last-reviewed: 2026-06-03
---

# Product Brief — WAF Anti-DDoS / Anti-Bot

## Business Context

Les hébergeurs web et développeurs indépendants ont besoin d'une protection WAF de niveau entreprise sans payer des milliers d'euros par mois à des prestataires cloud. Ce WAF est déployé auto-hébergé, entre Cloudflare (gratuit/Pro) et le serveur d'origine, pour combler le gap entre la protection réseau de Cloudflare et la sécurité applicative.

**Branding** : "Protected by GaetanDev.fr" — solution open-source communautaire.

## User Personas

### Persona 1 — Visiteur humain
- Navigue sur un site protégé par le WAF
- Voit la page de challenge pendant max 3 secondes lors de sa première visite
- Ensuite, navigation transparente pendant 24h (cookie de session)
- **Attente** : zéro friction après le premier challenge

### Persona 2 — Administrateur site
- Configure le WAF via fichier YAML
- Supervise via logs JSON et métriques Prometheus
- Gère les whitelists/blacklists via API admin ou fichier de config
- **Attente** : configuration simple, hot-reload, observabilité claire

### Persona 3 — Bot légitime (Googlebot, etc.)
- User-agent connu, IP dans les ranges officiels Google/Bing
- Doit passer sans challenge
- **Attente** : whitelist automatique par user-agent pattern + IP range

### Persona 4 — Attaquant / Bot malveillant
- Volume élevé de requêtes, user-agents faux ou absents
- Incapable d'exécuter JavaScript (headless sans fingerprint valide)
- **Attente** : blocage ou challenge systématique, log de l'événement

## Value Proposition

1. **Zéro CAPTCHA** : expérience utilisateur préservée, challenge JS transparent
2. **Performance** : < 5 ms latence ajoutée pour visiteurs connus
3. **Flexibilité** : configuration par domaine, règles personnalisables
4. **Observabilité** : logs JSON + Prometheus + Loki-compatible
5. **Déploiement simple** : binaire Go unique, config YAML, Docker-ready

## Risks & Mitigations

| Risque | Probabilité | Impact | Mitigation |
|--------|------------|--------|------------|
| Faux positifs (humains bloqués) | Moyen | Élevé | Seuils de score conservateurs, possibilité de désactiver le challenge par route |
| Bots avec JS activé (Playwright, Puppeteer) | Élevé | Moyen | Fingerprinting canvas/WebGL + timing + comportement |
| Attaque distribuée avec IPs légitimes | Moyen | Élevé | Score de confiance comportemental, pas uniquement IP-based |
| Surcharge mémoire (stockage état visiteurs) | Faible | Élevé | TTL sur entrées, limite max en mémoire, Redis optionnel |
| Contournement challenge par replay cookie | Faible | Moyen | Cookie signé HMAC avec IP binding, TTL court |

## Release Milestones

| Version | Périmètre | Cible |
|---------|-----------|-------|
| v0.1.0 | Reverse proxy de base + IP whitelist/blacklist + rate limiting | Phase 1 |
| v0.2.0 | JS Challenge + trust score + cookie de session | Phase 2 |
| v0.3.0 | Fingerprinting navigateur + détection bot avancée | Phase 3 |
| v0.4.0 | API admin REST + métriques Prometheus | Phase 4 |
| v1.0.0 | Production-ready, doc complète, tests conformance | Phase 5 |
