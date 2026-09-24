---
status: accepted
date: 2026-09-24
deciders: GaetanDev
relates-to: requirements.md (FR-03, FR-05, FR-06), schemas/config.schema.json (DomainConfig), CONFIG.md (domains), tasks.md (T13.1, Sprint 15, T16.22)
---

# ADR-022 — Retrait des surcharges `domains[]` jamais appliquées

## Context

`DomainConfig` déclarait quatre surcharges, acceptées par la validation,
décrites dans `config.schema.json`, `CONFIG.md` et `config.example.yaml` :

| Clé | Promesse documentée |
|---|---|
| `protected_paths` | challenge **toujours** servi sur ces préfixes |
| `public_paths` | challenge **jamais** servi sur ces préfixes |
| `rate_limit_override` | débit et burst propres au domaine |
| `trust_override` | seuils de challenge et de blocage propres au domaine |

Aucune n'était lue par le pipeline. Le constat date de T13.1 ; le Sprint 15 l'a
laissé hors périmètre (« demandent leurs propres specs »), en se contentant
d'un avertissement dans `CONFIG.md` ; T16.22 l'a renvoyé à une décision
d'opérateur. L'audit du 2026-09-24 (point 3.1) le relève à nouveau : un
opérateur qui configure `protected_paths: ["/admin/"]` ou un
`rate_limit_override` pour protéger une API voit le WAF démarrer sans erreur et
**ne rien appliquer**. C'est le pire des états : une protection affichée,
aucune protection effective, et rien dans les journaux pour le signaler.

## Options Evaluees

### Option A — Implémenter les quatre surcharges

- **+** Tient la promesse de la documentation.
- **-** Quatre fonctionnalités à spécifier (Gherkin, interaction avec
  `challenge_enabled`, le mode sous attaque, les fenêtres minute/heure du rate
  limiting, le hot-reload de `PATCH /waf/admin/config`) : un sprint à part
  entière, sans demande identifiée.

### Option B — Accepter les clés et avertir au démarrage

- **+** Aucun déploiement ne casse.
- **-** Laisse une option inerte dans le contrat, ce que le Sprint 15 a
  précisément combattu ; un avertissement de démarrage se perd dans les logs.

### Option C — Refuser les clés à la validation

- **+** Fail-fast : l'opérateur apprend au démarrage que la protection qu'il
  croyait configurer n'existe pas, avec la clé en cause et la raison.
- **+** Le contrat (`config.schema.json`) redevient le reflet exact du code.
- **-** **Rupture** : un fichier qui contient encore l'une de ces clés ne
  démarre plus. Il suffit de la retirer — son effet était nul.

## Decision

**Option C**, décision d'opérateur du 2026-09-24.

- Les quatre propriétés sont retirées de `DomainConfig` dans
  `config.schema.json`, de `config.example.yaml` et du tableau de `CONFIG.md`.
- `config.Validate` refuse chacune avec
  `domains[N].<clé> is not supported: it was accepted but never applied (ADR-022); remove it`.
  Le décodeur YAML strict les aurait déjà refusées une fois les champs
  supprimés, mais avec un « field not found » qui ne dit pas pourquoi : elles
  restent donc désérialisées dans un type sentinelle (`removedKey`), lu
  uniquement par la validation et exclu de toute sortie JSON.

## Consequences

- **Rupture de contrat de configuration** : c'est un changement MAJEUR du
  schéma `DomainConfig`, noté dans `changelog.md` avec sa migration (supprimer
  les clés). Aucun comportement d'exécution ne change : les clés n'en avaient
  aucun.
- Pour exempter des chemins du challenge, `static_assets` (FR-24) existe ; pour
  durcir un domaine, `challenge_enabled: true` et `server.strict_host`
  (ADR-020).
- Une implémentation future de l'une de ces surcharges passe par une nouvelle
  spec et réintroduit la clé comme ajout (MINEUR), sans reprendre ce code.

## Spec References

- `specs/schemas/config.schema.json` — `definitions.DomainConfig`
- `specs/requirements.md` FR-06 (challenge par domaine)
- `CONFIG.md` — section `domains`
- `specs/tasks.md` T13.1, Sprint 15, T16.22
