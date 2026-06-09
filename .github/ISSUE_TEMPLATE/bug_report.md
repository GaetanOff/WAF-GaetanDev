---
name: "🐛 Rapport de bug"
about: "Signaler un comportement inattendu ou une régression"
title: "bug: <description courte>"
labels: ["bug", "triage"]
assignees: []
---

## Description

<!-- Décrivez clairement le comportement observé. -->

## Comportement attendu

<!-- Que devrait-il se passer d'après la spec ? Citez le FR ou le fichier de spec si possible. -->

## Étapes pour reproduire

1.
2.
3.

## Environnement

| Champ | Valeur |
|---|---|
| Version du WAF (git sha / tag) | |
| Go version | |
| OS / distrib | |
| Mode déploiement | `docker-compose` / `binaire direct` / `k8s` |
| Devant Cloudflare ? | `oui` / `non` |

## Configuration utilisée

<!-- Copiez la section pertinente de config.yaml en **omettant toute valeur secrète**. -->

```yaml
# extrait de config.yaml (secrets masqués)
```

## Logs / erreurs

<!-- Copiez les lignes de log JSON pertinentes (log/slog). Masquez les IPs si nécessaire. -->

```json
```

## Contexte additionnel

<!-- Captures d'écran, traces réseau, comportement intermittent, etc. -->
