# Politique de sécurité

## Versions supportées

Seule la dernière version sur `main` reçoit des correctifs de sécurité.

| Branche / Tag | Supportée |
|---|---|
| `main` (HEAD) | ✅ |
| Versions antérieures | ❌ |

## Signaler une vulnérabilité

**Ne créez pas d'issue publique pour une vulnérabilité.**

Utilisez le canal **GitHub Security Advisories** (privé et chiffré) :

👉 [Ouvrir un advisory privé](https://github.com/GaetanOff/WAF-GaetanDev/security/advisories/new)

### Ce qu'il faut inclure dans le rapport

- Description de la vulnérabilité et de son impact
- Étapes pour reproduire (ou preuve de concept)
- Version / commit affecté
- Suggestion de correction si vous en avez une

### Ce à quoi vous pouvez vous attendre

| Étape | Délai cible |
|---|---|
| Accusé de réception | 48 h |
| Évaluation initiale (CVSS, périmètre) | 5 jours ouvrés |
| Correctif + advisory public | 30 jours (critique) / 90 jours (élevé/moyen) |

Une fois le correctif publié, vous serez crédité(e) dans le changelog et l'advisory (sauf si vous préférez rester anonyme).

## Périmètre

Ce projet est un **reverse proxy WAF** ; les rapports les plus critiques concernent :

- Bypass d'authentification ou de challenge JS
- Injection / exfiltration via les headers traités
- Contournement du rate limiting ou du score de confiance
- Fuite d'informations sensibles dans les logs ou les réponses d'erreur
- Vulnérabilités dans les dépendances Go directes

Les vulnérabilités dans les dépendances indirectes sont à signaler aux mainteneurs upstream.
