---
status: approved
last-reviewed: 2026-06-08
---

# Registre des traitements — WAF Anti-DDoS / Anti-Bot (FR-28, ADR-013)

Registre des traitements de données personnelles, conformément au RGPD
(art. 30). Le WAF traite des adresses IP, qui constituent des données à
caractère personnel.

## Données traitées

| Donnée | Finalité | Base légale | Conservation |
|--------|----------|-------------|--------------|
| Adresse IP (réelle, via `CF-Connecting-IP`) | Détection bot/DDoS, scoring de confiance, rate limiting | Intérêt légitime (sécurité du SI) | TTL `trust.score_ttl` (défaut 1h), puis purge automatique |
| `ip_hash` (SHA-256[:16]) | Corrélation des événements sans exposer l'IP | Intérêt légitime | Idem visiteur (purge) |
| User-Agent, JA3, empreinte navigateur | Détection d'automatisation | Intérêt légitime | Durée de la session de challenge |
| Journaux de sécurité (`SecurityEvent`) | Traçabilité, investigation d'incident | Intérêt légitime | Rétention des logs (hors WAF) |

## Mesures de protection

- **Anonymisation des logs** (`gdpr.anonymize_ip: true`) : l'IP est tronquée à
  /24 (IPv4) ou /48 (IPv6) dans les `SecurityEvent` ; seul l'`ip_hash` permet la
  corrélation, sans réversibilité vers l'IP complète.
- **Minimisation** : pas de query string dans les logs (path seul) ; pas de PII
  applicative collectée par le WAF.
- **Conservation limitée** : purge automatique des visiteurs au-delà du TTL
  (goroutine du store).
- **Droit à l'effacement** : `POST /waf/admin/gdpr/erase {"ip": "..."}` supprime
  immédiatement toutes les données d'un visiteur (par hash IP).
- **Pas de secret en clair** : secrets via variables d'environnement ; audit
  trail masque les secrets.

## Sous-traitants

- **Cloudflare** : terminaison TLS, fourniture de `CF-Connecting-IP` /
  `CF-IPCountry`. Voir l'accord de traitement Cloudflare.
- **AbuseIPDB** (optionnel, `threat_intel.abuseipdb`) : envoi de l'IP pour
  vérification de réputation. À déclarer comme sous-traitant si activé.
