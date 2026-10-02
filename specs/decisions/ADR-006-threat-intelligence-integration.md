---
status: accepted
date: 2026-06-03
deciders: GaetanDev
---

# ADR-006 — Intégration Threat Intelligence externe

## Context

Les systèmes de réputation IP externes (AbuseIPDB, Tor, ASN databases) apportent une dimension de connaissance globale que le WAF seul ne peut pas construire en local. Un bot venant d'une IP AbuseIPDB score 95 doit être traité différemment d'une IP inconnue.

## Contraintes

1. **Latence** : les lookups ne peuvent pas bloquer le pipeline de requêtes (P99 < 5 ms)
2. **Quotas** : AbuseIPDB gratuit = 1 000 req/jour → le cache est obligatoire
3. **Privacy** : les IPs des visiteurs ne doivent pas être envoyées inutilement à des tiers
4. **Résilience** : si le service externe est down → le WAF fonctionne sans la réputation

## Architecture retenue — Lookup asynchrone avec cache

```
Requête entrante
     │
     ▼
[Cache local] ─── HIT ──▶ Score appliqué immédiatement
     │
   MISS
     │
     ▼
[Channel async] ──▶ Goroutine lookup AbuseIPDB/Tor/ASN
     │                      │
     │                      ▼
     │              [Cache local mis à jour]
     │
     ▼
Décision courante : score sans réputation externe
(appliquée à la prochaine requête de cette IP)
```

Le lookup asynchrone garantit zéro latence ajoutée. L'inconvénient est que la première requête d'une IP inconnue se fait sans réputation — acceptable : la seconde requête bénéficiera du cache.

## Sources de données

| Source | Type | Fréquence update | Coût | Méthode |
|--------|------|-----------------|------|---------|
| AbuseIPDB | Réputation IP par score | Par lookup (avec cache) | Gratuit 1000/j | API REST |
| Tor exit nodes | Liste IPs | Toutes les heures | Gratuit | HTTP GET |
| ASN database | Mapping IP→ASN | Hebdomadaire | Gratuit (MaxMind GeoLite2-ASN) | Fichier local |
| IP2Location DB | Mapping IP→pays+ASN | Mensuel | Gratuit (lite) | Fichier local |
| Feeds YAML locaux | Listes custom | Watcher fichier | N/A | Fichier local |

## Stockage ASN

MaxMind GeoLite2-ASN est une base mmdb (binary) de ~8 MB chargée en mémoire au démarrage. Le lookup est O(log n) par IP, < 1 µs. Compatible avec `github.com/oschwald/maxminddb-golang`.

**Catégories ASN à surveiller :**
- Hosting providers (AWS AS16509, GCP AS15169, Azure AS8075, OVH AS16276, DigitalOcean AS14061, Hetzner AS24940)
- VPN providers (ExpressVPN, NordVPN, known ASNs)
- Tor : liste séparée (exit nodes, pas via ASN)

Les ASNs hosting déclenchent un delta score de -10 (pas un blocage — des humains utilisent AWS/VPN légitimement, mais c'est une indication).

## Confidentialité

- L'IP n'est envoyée à AbuseIPDB **que** si la feature est activée et que l'IP n'est pas déjà en cache
- Les IPs privées/RFC1918 ne sont jamais envoyées
- Un opt-in explicite `threat_intel.abuseipdb.enabled: true` est requis

## Conséquences

- Nouveau package `internal/threatintel/` avec :
  - `abuseipdb.go` : client API avec retry + cache
  - `tor.go` : fetcher liste + set lookup
  - `asn.go` : MaxMind mmdb loader + lookup
  - `feeds.go` : loader des feeds YAML locaux
  - `manager.go` : orchestration + channel async + cache unifié
- Dépendances : `github.com/oschwald/maxminddb-golang`
- Config : `threat_intel` section dans `config.schema.json`
- Nouvelle métrique : `waf_threat_intel_lookups_total{source,result}`

## Amendement — implémentation livrée (2026-10-02)

Constat d'audit : les conséquences ci-dessus décrivent une implémentation qui
n'a pas été livrée. L'implémentation réelle (FR-13 v2.9.1) :

- `internal/threatintel/threatintel.go` (`Checker` : cache TTL borné à
  100 000 verdicts, résolution asynchrone par un pool fixe de 16 workers, file de
  1 024 ; `StaticSource` : plages CIDR `blocklist_cidrs` / `suspect_cidrs`),
  `abuseipdb.go` (`HTTPSource`, sans retry : un échec vaut « propre », gardé une
  minute ; un `429` suspend les appels jusqu'au `Retry-After`) et
  `middleware.go`
- Ni liste Tor, ni base ASN MaxMind, ni feeds YAML : aucune dépendance
  `maxminddb-golang` ; des plages Tor ou datacenter ne sont prises en compte que
  saisies en CIDR
- Config : `threat_intel.enabled`, `cache_ttl`, `blocklist_cidrs`,
  `suspect_cidrs`, `abuseipdb.{enabled,url,api_key}`
- Aucune métrique dédiée : `waf_threat_intel_lookups_total` est différée

## Spec References

- [requirements-advanced.md](../requirements-advanced.md) FR-13
- [schemas/threat-intel-entry.schema.json](../schemas/threat-intel-entry.schema.json)
