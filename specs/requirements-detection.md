---
status: draft
version: 0.1.0
last-reviewed: 2026-06-08
extends: requirements-advanced.md (v2.0.0), requirements-ops.md
---

# Requirements Detection — Moteur de Risque & Décision (v4)

> Étend le système anti-bot / anti-DDoS existant pour le rendre **plus efficace
> tout en minimisant les faux positifs**. Les IDs FR-33 à FR-38 font suite aux
> FR-01 à FR-32 existants ; NFR-15 à NFR-17 font suite aux NFR-01 à NFR-14.
>
> **Ce document NE remplace PAS** les détecteurs existants (FR-07/08 anti-bot/DDoS,
> FR-11 JA3, FR-12 behavioral, FR-13 threat intel, FR-14 adaptive PoW, FR-15
> déception, FR-16 geo, FR-17 rules engine, FR-18 intégrité). Il introduit la
> **couche de fusion et de décision** qui les consomme.

---

## Problème & Discovery (protocole anti-vibe)

Le système actuel applique des `score_delta` indépendants au Trust Score, puis
décide par simple seuil. Conséquence : **un seul signal erroné** peut faire
passer un visiteur légitime sous le seuil de blocage → faux positif. À l'inverse,
un attaquant qui reste juste au-dessus de chaque seuil individuel passe.

- **WHO** — Acteurs : visiteur humain légitime, bot légitime vérifié (Googlebot…),
  bot malveillant / scraper / outil DDoS. Le moteur produit une décision
  consommée par le pipeline WAF (challenge, proxy, déception, blocage).
- **WHAT** — Entrée : l'ensemble des signaux déjà calculés (réputation, behavioral,
  JA3, fingerprint, geo, intégrité, rate). Transformation : fusion pondérée →
  `risk_score` [0..100] + `confidence` [0..1]. Sortie : une **décision graduée**
  (ALLOW / OBSERVE / THROTTLE / CHALLENGE / TARPIT / BLOCK) + une `RiskAssessment`
  explicable.
- **WHEN** — À chaque requête, après collecte des signaux (synchrones) et lecture
  des signaux asynchrones disponibles. Cas limites : signaux manquants (cache
  miss threat intel, pas de JA3), premier contact (aucun historique).
- **WHY WRONG** — Échec = blocage d'un humain légitime (faux positif) OU passage
  d'un attaquant (faux négatif). Le faux positif est jugé **plus coûteux** ici :
  la conception favorise les mitigations **réversibles** (challenge) plutôt que le
  blocage dur, sauf preuve corroborée.
- **DONE** — Critères : (1) un signal heuristique isolé ne peut jamais produire un
  BLOCK dur ; (2) un bot vérifié par reverse-DNS n'est jamais bloqué par
  heuristique ; (3) tout BLOCK heuristique exige ≥ 2 familles de signaux
  corroborantes ; (4) chaque décision est explicable (RiskAssessment loggée) ;
  (5) taux de faux positifs humains < 0,1 % (NFR-15).

---

## FR-33 — Moteur de Scoring de Risque (fusion de signaux)

- Le WAF DOIT calculer, par requête, un **Risk Score** unique `[0..100]`
  (0 = certainement humain, 100 = certainement malveillant) par **fusion pondérée**
  des familles de signaux existantes :
  - `reputation` (FR-13 : AbuseIPDB, Tor, ASN datacenter)
  - `behavioral` (FR-12 : Behavioral Anomaly Score)
  - `tls` (FR-11 : JA3 connu malveillant / swap de fingerprint)
  - `fingerprint` (FR-07 : signaux navigateur headless)
  - `integrity` (FR-18 : obfuscation de path, patterns d'injection)
  - `rate` (FR-03/08 : dépassement de débit, burst)
  - `geo` (FR-16 : pays à risque)
- Chaque famille DOIT produire une **contribution normalisée** `[0..100]` et un
  **poids** configurable. Le Risk Score est la combinaison pondérée bornée à 100.
- Le moteur DOIT calculer un **niveau de confiance** `confidence [0..1]` reflétant
  la **quantité et la qualité** des signaux disponibles (peu de signaux → faible
  confiance). Une décision dure (BLOCK) NE DOIT PAS être prise à faible confiance.
- Le moteur DOIT produire une `RiskAssessment` explicable (cf.
  `schemas/risk-assessment.schema.json`) listant chaque facteur contributif
  (famille, signal, valeur, poids, contribution).
- Les poids et seuils DOIVENT être configurables et **profilables** (`balanced`,
  `strict`, `lenient`) sans recompilation.
- La fusion DOIT être **déterministe** : mêmes signaux → même décision (testable).

## FR-34 — Échelle de Mitigation Graduée (réversible)

- Le WAF DOIT mapper `(risk_score, confidence)` vers une décision parmi une
  **échelle graduée et croissante en sévérité** :
  1. `ALLOW` — transmis sans friction
  2. `OBSERVE` — transmis mais marqué pour analyse renforcée (monitor)
  3. `THROTTLE` — transmis avec rate limit réduit pour ce visiteur
  4. `CHALLENGE` — challenge JS (mitigation **réversible** : l'humain récupère)
  5. `TARPIT` — réponse ralentie (FR-15), pour bots à coût d'attaque élevé
  6. `BLOCK` — HTTP 403 (mitigation **terminale**)
- Toute mitigation non-terminale (≤ CHALLENGE) DOIT être **réversible** : un
  visiteur qui prouve son humanité remonte dans l'échelle.
- Le WAF NE DOIT escalader à `BLOCK` que si les conditions de FR-35 sont réunies.
- Le mapping DOIT être configurable (bornes de score par tier) et profilable.

## FR-35 — Exigence de Corroboration (cœur anti-faux-positif)

- Un **BLOCK dur heuristique** DOIT exiger **au moins 2 familles de signaux
  indépendantes** dépassant chacune leur seuil de contribution
  (`corroborating_families ≥ 2`).
- Un **signal isolé** (une seule famille) NE DOIT JAMAIS produire un BLOCK :
  au pire `CHALLENGE`.
- Les **signaux déterministes** suivants SONT exemptés de l'exigence de
  corroboration et PEUVENT bloquer seuls (vérité non-ambiguë) :
  - IP/CIDR en **blacklist explicite** (FR-04)
  - Déclenchement d'un **honeypot** (FR-15) ou chemin honeypot (FR-07)
  - Hash **JA3 explicitement blacklisté** (FR-11)
  - Réputation threat-intel **confirmée critique** (AbuseIPDB ≥ 80, FR-13)
  - **Circuit breaker** ouvert pour l'IP (FR-08)
- À confiance insuffisante (`confidence < block_min_confidence`), la décision DOIT
  être plafonnée à `CHALLENGE` même si le risk score est élevé.

## FR-36 — Allowlist de Bots Vérifiés (anti-faux-positif crawlers)

- Le WAF DOIT vérifier l'authenticité des crawlers déclarés par **reverse-DNS +
  forward-confirm** (rDNS de l'IP → hostname attendu, puis résolution directe du
  hostname → doit re-contenir l'IP). Couvre au minimum : Googlebot, Bingbot,
  DuckDuckBot, Applebot.
- Un crawler **vérifié** DOIT être placé en `ALLOW` et NE DOIT JAMAIS être bloqué
  ni challengé par une décision **heuristique** (il reste soumis au rate limiting
  global et aux blacklists explicites).
- Un user-agent de crawler **non vérifié** (rDNS ne correspond pas) DOIT être
  traité comme suspect (contribution `reputation` augmentée) — neutralise le
  spoofing de `Googlebot`.
- Le résultat de vérification DOIT être mis en cache avec TTL configurable.
- La vérification rDNS DOIT être **asynchrone / non bloquante** : sur cache miss,
  la décision courante utilise l'état connu (cf. NFR-08).

## FR-37 — Crédits de Preuve Humaine & Trust Persistant

- Le moteur DOIT **réduire le Risk Score** (crédit) en présence de preuves
  positives d'humanité :
  - Challenge JS **réussi** récemment (cookie de session valide, FR-06)
  - Fingerprint + JA3 **stables** sur plusieurs sessions (cohérence = humain)
  - (Optionnel, opt-in) signaux d'**interaction client** (mouvement souris,
    saisie clavier, événements de défilement) collectés par la page challenge
- Un visiteur ayant **réussi un challenge** DOIT bénéficier d'un **trust
  persistant ("sticky trust")** pendant un TTL configurable : il NE DOIT PAS être
  re-challengé à chaque requête tant que son comportement reste cohérent.
- Le sticky trust DOIT être **révoqué** si un signal **déterministe** (FR-35) se
  déclenche (ex : suit un honeypot, passe en blacklist).
- Les crédits humains agissent comme **garde-fous anti-FP** : un visiteur avec
  preuve d'humanité forte NE DOIT pas être bloqué par heuristique seule.

## FR-38 — Garde-fous Faux Positifs & Mode Shadow

- Toute nouvelle règle, tout nouveau seuil DOIT pouvoir être déployé en **mode
  shadow** (log-only) : la décision est **calculée et journalisée** mais **non
  appliquée**, afin de mesurer l'impact FP avant activation.
- Le WAF DOIT implémenter une **boucle de feedback FP** : lorsqu'un visiteur
  flaggé (CHALLENGE) **réussit** le challenge, le poids des familles ayant
  contribué à tort DOIT décroître pour ce visiteur (apprentissage local borné),
  et un compteur de "faux positif probable" DOIT être incrémenté.
- Le WAF DOIT toujours offrir un **chemin de récupération** : pour toute décision
  fondée sur des signaux non-déterministes, un `CHALLENGE` DOIT précéder tout
  `BLOCK` (l'humain a toujours une chance de prouver son humanité).
- Le WAF DOIT exposer des métriques FP :
  - `waf_decisions_total{tier}` (répartition des décisions)
  - `waf_challenge_pass_after_flag_total` (proxy de faux positifs évités)
  - `waf_hard_blocks_total{corroborated}` (blocs durs, corroborés ou déterministes)
  - `waf_verified_bot_total{bot}` (crawlers vérifiés)
- Le mode shadow et les profils DOIVENT être commutables à chaud (API admin / SIGHUP).

---

## Non-Functional Requirements additionnels

### NFR-15 — SLO Faux Positifs
- Le taux de **blocage dur de visiteurs humains légitimes** DOIT rester
  **< 0,1 %** (cohérent avec la métrique de succès de `mission.md`).
- Proxy de mesure : ratio `challenge_pass_after_hard_signal / total_humans`.
  Une alerte DOIT se déclencher si le taux estimé dépasse le budget.
- Tout déploiement d'une règle augmentant les blocages DOIT passer par une phase
  **shadow** (FR-38) d'au moins 24 h avant activation en production.

### NFR-16 — Latence du Moteur de Décision
- La fusion + la décision (partie **synchrone**, signaux déjà calculés) DOIT
  s'exécuter en **< 50 µs** CPU par requête.
- Le moteur NE DOIT PAS effectuer d'I/O bloquante : tout signal nécessitant un
  lookup réseau (rDNS, threat intel) est asynchrone et consommé depuis le cache.
- Conforme au budget global NFR-01 (P99 < 5 ms).

### NFR-17 — Explicabilité & Auditabilité
- Chaque décision DOIT produire une `RiskAssessment` listant les facteurs
  contributifs, le score, la confiance, le nombre de familles corroborantes et le
  tier décidé.
- La `RiskAssessment` DOIT être incluse (forme condensée) dans l'événement de
  sécurité loggé (FR-09) via les champs `reason` et un `score_delta` explicite.
- En mode debug, l'API admin DOIT pouvoir retourner la `RiskAssessment` complète
  d'une requête échantillonnée (sans exposer de PII au-delà de l'`ip_hash`).

---

## Spec References

- Détecteurs consommés : requirements.md FR-03..FR-08, requirements-advanced.md
  FR-11..FR-18, requirements-ops.md
- [ADR-015](decisions/ADR-015-risk-scoring-decision-engine.md) — décision d'architecture
- [features/risk-scoring-engine.feature](features/risk-scoring-engine.feature) — comportements
- [schemas/risk-assessment.schema.json](schemas/risk-assessment.schema.json) — contrat de données
- [mission.md](mission.md) — métrique de succès faux positifs < 0,1 %
