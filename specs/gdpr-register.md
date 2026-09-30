---
status: approved
last-reviewed: 2026-09-30
---

# Registre des traitements — WAF Anti-DDoS / Anti-Bot (FR-28, ADR-013)

Registre des traitements de données personnelles, conformément au RGPD
(art. 30). Le WAF traite des adresses IP, qui constituent des données à
caractère personnel.

## Données traitées

| Donnée | Finalité | Base légale | Conservation |
|--------|----------|-------------|--------------|
| Adresse IP (réelle, via `CF-Connecting-IP`) | Détection bot/DDoS, scoring de confiance, rate limiting | Intérêt légitime (sécurité du SI) | TTL `trust.score_ttl` (défaut 1h), puis purge automatique |
| `ip_hash` (HMAC-SHA256 à clé[:16], IPv6 par /64) | Corrélation des événements sans exposer l'IP | Intérêt légitime | Idem visiteur (purge) |
| User-Agent, JA3, empreinte navigateur | Détection d'automatisation | Intérêt légitime | Durée de la session de challenge |
| Journaux de sécurité (`SecurityEvent`) | Traçabilité, investigation d'incident | Intérêt légitime | Flux admin en mémoire : 10 000 dernières mitigations, non servies au-delà de 24 h ; journal sur la sortie standard : rétention des logs (hors WAF) |
| Audit trail admin (cible de l'action : IP de whitelist/blacklist ou `ip_hash`) | Traçabilité des actions d'administration | Intérêt légitime | `audit.max_entries` entrées en mémoire (1 000 par défaut) ; fichier `audit.file` : rotation par l'opérateur |

## Mesures de protection

- **Anonymisation des logs** (`gdpr.anonymize_ip: true`) : l'IP est tronquée à
  /24 (IPv4) ou /48 (IPv6) dans les `SecurityEvent` ; seul l'`ip_hash` permet la
  corrélation. C'est un HMAC dont la clé dérive de `challenge.secret_key` : sans
  la clé, il ne se renverse pas en énumérant les adresses. Donnée pseudonymisée,
  il reste une donnée personnelle au sens du RGPD.
- **Minimisation** : pas de query string dans les logs (path seul) ; pas de PII
  applicative collectée par le WAF.
- **Conservation limitée** : purge automatique des visiteurs au-delà du TTL
  (goroutine du store).
- **Droit à l'effacement** : `POST /waf/admin/gdpr/erase {"ip": "..."}` (ou
  `DELETE /waf/admin/visitors/{ip_hash}`) supprime immédiatement toutes les
  données d'un visiteur (par hash IP) : état de confiance, buckets de rate limit,
  profil comportemental, dernier JA3. Les événements de sécurité passés restent
  soumis à leur rétention.
- **Pas de secret en clair** : secrets via variables d'environnement ; audit
  trail masque les secrets.

## Sous-traitants

- **Cloudflare** : terminaison TLS, fourniture de `CF-Connecting-IP` /
  `CF-IPCountry`. Voir l'accord de traitement Cloudflare.
- **AbuseIPDB** (optionnel, `threat_intel.abuseipdb`) : envoi de l'IP pour
  vérification de réputation. À déclarer comme sous-traitant si activé.
