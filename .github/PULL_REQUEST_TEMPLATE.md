## Résumé

<!-- 2-3 bullet points sur ce que fait cette PR et pourquoi. -->

- 
- 

## Références

<!-- Issues fermées, specs modifiées, ADRs créés. -->

- Closes #
- Spec : `specs/...`

---

## Checklist SDD — 7 gates

> Cochez chaque gate avant de demander une review. Une PR sans checklist complète ne sera pas mergée.

### Spécification
- [ ] **G0 — Spec** : toute nouvelle fonctionnalité a une spec `approved` dans `specs/` ; aucun code avant spec
- [ ] **G0 — Pas de breaking change silencieux** : si breaking change → version MAJOR + ADR dans `specs/decisions/`

### Qualité technique
- [ ] **G1 — Spec lint** : `spectral lint` passe sans erreur
- [ ] **G2 — Type check** : `go build ./...` + `go vet ./...` sans erreur
- [ ] **G3 — Conformance API** : réponses HTTP conformes à l'OpenAPI (status codes, schémas, headers)
- [ ] **G4 — Tests** : `go test ./...` passe ; couverture ≥ 80 % sur la logique métier ajoutée
- [ ] **G5 — Sécurité** : pas de nouveau `nosemgrep` / `nolint` sans commentaire justificatif ; pas de secret en clair

### Release
- [ ] **G6 — Performance** : pas de régression observable sur les benchmarks existants
- [ ] **G7 — Review humaine** : au moins un reviewer a relu le diff complet

---

## Plan de test

<!-- Comment vérifier manuellement que ça fonctionne ? -->

- [ ] 
- [ ] 

## Captures / logs (si pertinent)

<!-- Collage de logs JSON, sortie de `go test -v`, trace Prometheus, etc. -->
