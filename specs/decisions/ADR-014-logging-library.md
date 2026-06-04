---
status: accepted
date: 2026-06-04
deciders: GaetanDev
supersedes: Implicit zerolog choice in ADR-001 (Consequences) and plan.md (Slice 4.1)
---

# ADR-014 — Bibliothèque de logging : log/slog (stdlib) vs zerolog

## Context

Le WAF doit émettre un événement de sécurité JSON structuré par requête,
conforme à `specs/schemas/security-event.schema.json` (corrélé par `request_id`,
champs imposés, `additionalProperties: false`). L'implémentation initiale
(Slice 4.1) utilisait `github.com/rs/zerolog`.

Depuis Go 1.21, la bibliothèque standard fournit `log/slog`, un logger
structuré officiel et stable. La question est de savoir si une dépendance
tierce de logging reste justifiée pour ce projet.

## Options Évaluées

### Option A — `log/slog` (bibliothèque standard)

**Avantages :**
- Zéro dépendance externe : moins de surface d'attaque, moins de CVE à suivre,
  build plus simple (cohérent avec « `net/http` stdlib suffit » d'ADR-001).
- Stabilité garantie par la compatibilité Go 1.x.
- `JSONHandler` produit du JSON structuré ; `ReplaceAttr` permet de retirer les
  clés intégrées (`time`, `level`, `msg`) pour respecter le schéma.
- API d'attributs typés (`slog.String`, `slog.Int`, `slog.Any`) suffisante pour
  l'événement de sécurité.

**Inconvénients :**
- Performances brutes inférieures à zerolog (zerolog est zéro-allocation) sur
  des micro-benchmarks de logging.

### Option B — `github.com/rs/zerolog`

**Avantages :**
- Logging zéro-allocation, très haut débit.
- API fluide (`.Str().Int().Send()`).

**Inconvénients :**
- Dépendance externe (+ transitives `mattn/go-colorable`, `mattn/go-isatty`).
- Émet `.Log()` sans niveau pour contourner le filtre — comportement à
  reproduire soigneusement.

## Decision

**`log/slog` (bibliothèque standard) est choisi.** zerolog est retiré.

Raisons déterminantes :
1. **Une dépendance en moins** : un seul événement de sécurité est émis par
   requête ; le coût de logging n'est pas le goulot d'étranglement du NFR
   P99 < 5 ms (dominé par le proxy et le PoW, pas par la sérialisation du log).
2. **Stdlib d'abord** : cohérent avec la philosophie d'ADR-001 (`net/http`
   stdlib, pas de framework lourd).
3. **Conformité au schéma** préservée : `ReplaceAttr` retire `time`/`level`/`msg`,
   les champs nullables sont émis en `null`, l'événement reste validé par
   `security-event.schema.json`.

Le « toujours émis » de zerolog (`.Log()` sans niveau) est reproduit en
journalisant l'événement de sécurité au niveau configuré du handler, qui passe
donc toujours le filtre.

## Consequences

- `internal/logger` dépend uniquement de `log/slog` (stdlib).
- `github.com/rs/zerolog` est retiré de `go.mod` / `go.sum` (ainsi que ses
  dépendances transitives).
- `ADR-001` (Consequences) et `plan.md` (Slice 4.1, liste des dépendances) sont
  mis à jour pour ne plus citer zerolog.
- Un test de conformance verrouille l'absence de clés hors schéma dans la sortie.

## Spec References

- [requirements.md](../requirements.md) FR-09 (Logging), NFR-01 (Performance)
- [schemas/security-event.schema.json](../schemas/security-event.schema.json)
- [ADR-001](ADR-001-go-language-choice.md) — choix du langage et philosophie stdlib
