---
status: proposed
date: 2026-06-09
deciders: GaetanDev
relates-to: requirements.md (FR-08), requirements-detection.md (FR-33..FR-35)
---

# ADR-016 — Pression globale adaptative au lieu du 503 global

## Context

FR-08 v1 imposait un mode degrade global : au-dessus d'un seuil de req/s total,
les nouveaux visiteurs recevaient `503 Service Unavailable` avec `Retry-After`.

Ce comportement protege l'origine, mais il cree un risque de faux positifs
massif pendant un pic legitime : campagne marketing, cache miss CDN, crawler
legitime, redemarrage de clients, ou attaque melangee a du trafic humain. Il
coupe aussi le chemin de recuperation humain alors que le reste du WAF possede
deja des mitigations reversibles : challenge JS, PoW adaptatif, throttling,
tarpit et moteur de risque gradue.

## Options Evaluees

### Option A — Conserver le 503 global

- **+** Simple, protege vite l'origine.
- **-** Faux positifs eleves, tous les nouveaux visiteurs sont traites comme
  suspects, mauvais comportement si le VPS peut absorber le volume.

### Option B — Monter fortement le seuil global

- **+** Reduit les faux positifs sur petits pics.
- **-** Ne corrige pas le modele de decision ; au-dela du nouveau seuil, le
  comportement reste brutal.

### Option C — Remplacer le blocage global par une pression adaptative

- **+** Le volume global devient un signal, pas une sentence. Les visiteurs
  connus restent favorises, les inconnus/suspects paient plus de friction, et
  les abus par IP restent limites par `429` / circuit-breaker.
- **+** Compatible avec ADR-015 : decision graduee, reversible et explicable.
- **-** Demande de cabler la pression vers plusieurs composants au lieu d'un
  unique middleware bloquant.

## Decision

**Option C est retenue.** Le WAF calcule un niveau de pression global :
`normal`, `elevated`, `high`, `critical`.

La pression globale :

- NE DOIT PAS produire seule un `503`, `403` ou blocage complet.
- DOIT alimenter les signaux `rate` / `global_pressure` du moteur de risque.
- DOIT renforcer les mitigations reversibles : challenge plus frequent,
  difficulte PoW accrue, throttling des visiteurs inconnus ou suspects.
- DOIT favoriser les visiteurs connus, cookies valides et bots verifies, sous
  reserve des controles par IP, blacklists et triggers deterministes.
- DOIT etre exposee dans les logs et metriques.

Les controles durs restent reserves aux signaux deterministes ou locaux :
blacklist, honeypot, circuit-breaker par IP, threat-intel critique, JA3
blackliste, et rate limit par IP (`429`).

## Consequences

- FR-08 passe en version draft breaking (`requirements.md` v2.0.0-draft).
- Le scenario Gherkin `Seuil global de trafic depasse` est remplace par des
  scenarios de pression adaptative.
- Le schema de configuration ajoute `antiddos.pressure_levels`.
- L'ancien comportement T3.2 est deprecie et remplace par T10.1.
- L'implementation devra remplacer le compteur global a slice de timestamps par
  un compteur a cout borne (fenetre fixe ou anneau de buckets).

## Spec References

- [requirements.md](../requirements.md) FR-08
- [requirements-detection.md](../requirements-detection.md) articulation FR-03/FR-08/FR-35
- [features/anti-ddos.feature](../features/anti-ddos.feature)
- [schemas/config.schema.json](../schemas/config.schema.json)
