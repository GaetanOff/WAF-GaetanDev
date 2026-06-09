---
name: "📐 Écart de spec (Spec Gap)"
about: "Signaler une divergence entre le code et les specs, ou une zone non spécifiée"
title: "spec-gap: <description courte>"
labels: ["spec-gap", "triage"]
assignees: []
---

> **Note SDD** : Toute divergence entre le code et une spec `approved` est une régression de spec.
> Le code doit être corrigé **ou** la spec doit être mise à jour via une PR dédiée — jamais silencieusement.

## Type d'écart

- [ ] Le code ne respecte pas une spec `approved`
- [ ] Une fonctionnalité est implémentée sans spec correspondante
- [ ] Une spec référencée n'existe pas ou est incomplète
- [ ] La spec est `draft` mais du code l'implémente déjà
- [ ] Autre : <!-- précisez -->

## Fichier(s) de spec concerné(s)

<!-- Ex: specs/api/waf.openapi.yaml, specs/features/challenge.feature, specs/schemas/config.schema.json -->

- `specs/...`

## Fichier(s) de code concerné(s)

<!-- Ex: internal/middleware/challenge/cookie.go:59 -->

- `internal/...`

## Description de l'écart

<!-- Citez la clause de spec (FR-XX, opération OpenAPI, scénario Gherkin…)
     et expliquez en quoi le code s'en écarte. -->

**Spec dit :**

> (citation ou référence exacte)

**Code fait :**

> (description du comportement réel)

## Impact

<!-- Quel est l'impact opérationnel de cet écart ?
     Ex : faux-positifs de challenge, bypass de rate limit, métriques incorrectes… -->

## Suggestion de résolution

<!-- Option A : corriger le code pour respecter la spec.
     Option B : ouvrir une PR de spec pour formaliser le comportement actuel. -->
