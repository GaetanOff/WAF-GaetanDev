---
status: accepted
date: 2026-06-03
deciders: GaetanDev
---

# ADR-013 — Conformité GDPR & Privacy by Design

## Context

Le WAF traite des adresses IP, qui sont des données personnelles selon le RGPD (Article 4). En tant que composant d'infrastructure traitant ces données, il doit être conforme au RGPD pour les déploiements dans l'Union Européenne.

## Données personnelles traitées

| Donnée | Finalité | Base légale |
|--------|----------|-------------|
| Adresse IP | Sécurité (blocage, scoring) | Intérêt légitime (Article 6.1.f) |
| User-Agent | Détection bot | Intérêt légitime |
| Fingerprint navigateur | Authentification challenge | Intérêt légitime |
| JA3 TLS | Détection bot avancée | Intérêt légitime |
| Chemins visités | Analyse comportementale | Intérêt légitime |

**Durée de conservation par défaut** :
- `VisitorState` en mémoire : 1h (TTL configurable, RGPD recommande minimum nécessaire)
- Security events en mémoire : 24h
- Audit trail admin : 30 jours

## IP Anonymisation

Deux modes disponibles :

**Mode pseudonymisation** (défaut) : l'IP est stockée en clair dans les `VisitorState` internes pour la sécurité, mais hashée (SHA-256 non réversible) dans les logs et métriques.

**Mode anonymisation** (`privacy.anonymize_ip: true`) : l'IP est tronquée avant tout stockage :
- IPv4 : `/24` — `192.168.1.x` (dernier octet → 0)
- IPv6 : `/48` — les 80 derniers bits → 0

En mode anonymisation, la protection IP-based est légèrement dégradée (plusieurs visiteurs partagent le même `/24`) — trade-off acceptable configuré explicitement par l'opérateur.

## Droit à l'effacement (Article 17)

L'endpoint `DELETE /waf/admin/visitors/{ip_hash}` supprime immédiatement :
1. L'entrée dans le `VisitorState` store
2. Les buckets de rate limit associés
3. Le profil comportemental

Il ne supprime pas les security events passés (finalité sécurité, conservation limitée).

## Transferts internationaux

Le WAF ne transfère pas de données personnelles à des tiers sauf si `threat_intel.abuseipdb.enabled: true`. Dans ce cas :
- Les IPs sont envoyées à AbuseIPDB (hébergé aux USA) → nécessite mention dans la politique de confidentialité du site
- L'opérateur est responsable de cette conformité
- Le WAF DOIT documenter clairement ce transfert dans le README

## Minimisation des données

- Les fingerprints sont toujours stockés hashés (pas de données brutes)
- Les query parameters ne sont pas loggés en clair
- La profondeur d'analyse comportementale est limitée à N requêtes (ring buffer)
- Les nonces de challenge expirent en 30s (pas de stockage long)

## Registre des traitements (Article 30)

Le README DOIT contenir un tableau de registre des traitements :

| Traitement | Données | Durée | Destinataires | Base légale |
|-----------|---------|-------|---------------|-------------|
| Sécurité réseau | IP, UA, path | 1h mémoire | Aucun (sauf AbuseIPDB si configuré) | Intérêt légitime |
| Logs de sécurité | IP hashée, domain, path | 24h mémoire | Aucun | Intérêt légitime |
| Audit admin | Action, endpoint, IP admin | 30 jours | Aucun | Intérêt légitime |

## Conséquences

- Config : bloc `privacy` dans config.schema.json
- `internal/privacy/anonymizer.go` : fonctions de truncation IPv4/IPv6
- `internal/privacy/retention.go` : goroutine de purge avec TTL policy
- `GET /waf/admin/privacy/report` : rapport du registre des traitements (JSON)
- Documentation RGPD dans README.md section dédiée
- Pas de changement d'architecture majeur (privacy by design from the start)

## Spec References

- [requirements-ops.md](../requirements-ops.md) FR-28
- [features/gdpr-compliance.feature](../features/gdpr-compliance.feature)
