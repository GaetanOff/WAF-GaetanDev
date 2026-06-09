---
name: "✨ Demande de fonctionnalité"
about: "Proposer une nouvelle fonctionnalité ou une amélioration"
title: "feat: <description courte>"
labels: ["enhancement", "triage"]
assignees: []
---

## Problème / contexte

<!-- Quel est le problème que vous cherchez à résoudre ?
     Qui est l'acteur concerné (visiteur, opérateur, système externe) ? -->

## Solution proposée

<!-- Décrivez la fonctionnalité souhaitée de façon précise.
     Si vous avez une idée d'implémentation, exposez-la ici. -->

## Critères d'acceptation (Gherkin)

<!-- Formalisez la fonctionnalité en scénarios Given / When / Then.
     Ces scénarios deviendront la base du fichier .feature si la FR est acceptée. -->

```gherkin
Scenario: <cas nominal>
  Given ...
  When  ...
  Then  ...

Scenario: <cas d'erreur>
  Given ...
  When  ...
  Then  ...
```

## Domaine fonctionnel concerné

<!-- Cochez les domaines impactés. -->

- [ ] Reverse proxy / routing
- [ ] Extraction IP (Cloudflare / direct)
- [ ] Rate limiting
- [ ] Whitelist / Blacklist
- [ ] Score de confiance
- [ ] Challenge JavaScript
- [ ] Anti-bot / honeypot
- [ ] Anti-DDoS / circuit breaker
- [ ] Observabilité (logs, métriques, traces)
- [ ] API d'administration
- [ ] Fingerprinting TLS (JA3)
- [ ] Mode maintenance
- [ ] Configuration / déploiement
- [ ] Autre : <!-- précisez -->

## Alternatives envisagées

<!-- Avez-vous considéré d'autres approches ? Pourquoi les écartez-vous ? -->

## Contexte additionnel

<!-- Liens vers des RFC, projets similaires, benchmarks, etc. -->
