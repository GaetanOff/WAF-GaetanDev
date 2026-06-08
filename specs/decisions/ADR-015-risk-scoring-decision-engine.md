---
status: accepted
date: 2026-06-08
deciders: GaetanDev
relates-to: requirements-detection.md (FR-33..FR-38)
---

# ADR-015 — Moteur de Scoring de Risque & Décision graduée

## Context

Le WAF dispose de nombreux détecteurs indépendants (réputation, behavioral, JA3,
fingerprint, intégrité, rate, geo). Chacun applique un `score_delta` au Trust
Score, et la décision finale est un **simple seuil** sur le score agrégé
(`challenge_threshold`, `block_threshold`).

Ce modèle pose deux problèmes opposés :
1. **Faux positifs** : un seul détecteur erroné (ex : IP datacenter d'un VPN
   grand public, JA3 d'un navigateur peu courant) peut suffire à faire passer un
   humain légitime sous le seuil de blocage.
2. **Faux négatifs** : un attaquant qui reste juste sous chaque seuil individuel
   accumule des deltas sans jamais déclencher une décision dure.

L'objectif (cf. `mission.md`) est une protection **très efficace avec < 0,1 % de
faux positifs**. Il faut donc une couche de **décision** plus riche qu'un seuil.

## Options Évaluées

### Option A — Conserver le seuil simple sur Trust Score
- **+** Déjà implémenté, trivial, rapide.
- **−** Ne distingue pas "1 signal fort" de "3 signaux faibles" ; pas de notion de
  confiance ; FP structurels ; non explicable.

### Option B — Modèle ML (classifieur entraîné)
- **+** Potentiellement le plus précis.
- **−** Boîte noire (non explicable, NFR-17 violé), nécessite un pipeline de
  données/entraînement, dérive, dépendances lourdes (contraire à la philosophie
  stdlib d'ADR-001), difficile à tester de façon déterministe (SDD).

### Option C — Moteur de fusion pondérée + décision graduée + corroboration
- **+** Déterministe et **testable** (SDD) ; **explicable** (RiskAssessment) ;
  permet la **corroboration** (≥ 2 familles pour un BLOCK) qui attaque
  directement la cause des FP ; mitigations **graduées et réversibles** ;
  profils de pondération ajustables sans recompilation ; mode shadow.
- **−** Pondérations à calibrer manuellement (atténué par le mode shadow et la
  boucle de feedback FP).

## Decision

**Option C est retenue.** Un moteur de scoring de risque fusionne les
contributions normalisées des familles de signaux en un `risk_score` + une
`confidence`, puis mappe le couple vers une **échelle de mitigation graduée**
(ALLOW → OBSERVE → THROTTLE → CHALLENGE → TARPIT → BLOCK).

Principes anti-faux-positifs (non négociables) :
1. **Corroboration** : un BLOCK dur heuristique exige ≥ 2 familles indépendantes
   au-dessus de leur seuil ; un signal isolé plafonne à CHALLENGE (FR-35).
2. **Signaux déterministes exemptés** : blacklist, honeypot, JA3 blacklisté,
   threat-intel critique, circuit breaker PEUVENT bloquer seuls (vérité non
   ambiguë).
3. **Bots vérifiés** (reverse-DNS forward-confirm) et **preuves d'humanité**
   (challenge réussi, fingerprint stable) agissent comme garde-fous : jamais de
   BLOCK heuristique contre eux (FR-36/FR-37).
4. **Réversibilité** : toute décision non déterministe offre un CHALLENGE avant
   tout BLOCK (chemin de récupération).
5. **Confiance** : pas de décision dure à faible confiance (peu de signaux).
6. **Shadow mode** + boucle de feedback FP pour calibrer sans risque (FR-38).

Le moteur **consomme** les détecteurs existants sans les remplacer ; il remplace
uniquement la logique de décision finale (le seuil simple).

## Consequences

- Nouveau sous-système `internal/risk` (proposé) : fusion, profils, décision,
  RiskAssessment. Le middleware de décision se place **après** les détecteurs et
  **avant** le proxy, en remplacement du seuil actuel du Trust Score.
- Le Trust Score (FR-05) reste la mémoire persistante par visiteur ; le Risk
  Score est la **décision instantanée** par requête. Les crédits humains (FR-37)
  relient les deux (le trust persistant abaisse le risque).
- Latence synchrone ajoutée bornée à < 50 µs (NFR-16) ; aucun I/O bloquant.
- Calibration : pondérations/seuils dans la config, profilables, déployables en
  shadow avant activation (NFR-15 exige ≥ 24 h de shadow pour toute règle
  durcissante).
- Explicabilité : RiskAssessment loggée (NFR-17), exposée en debug via l'API admin.
- Pas de dépendance externe (cohérent ADR-001/ADR-014).

## Spec References

- [requirements-detection.md](../requirements-detection.md) FR-33..FR-38, NFR-15..NFR-17
- [requirements-advanced.md](../requirements-advanced.md) FR-11..FR-18 (signaux consommés)
- [schemas/risk-assessment.schema.json](../schemas/risk-assessment.schema.json)
- [ADR-009](ADR-009-behavioral-analysis.md), [ADR-010](ADR-010-adaptive-difficulty.md) (détecteurs amont)
- [mission.md](../mission.md) — SLO faux positifs < 0,1 %
