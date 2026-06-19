---
status: accepted
date: 2026-06-19
deciders: GaetanDev
relates-to: requirements.md (FR-08 v2.0.0), requirements-detection.md (FR-33..FR-39), features/anti-ddos.feature, ADR-016
---

# ADR-018 — Mode « sous attaque » : challenge forcé piloté par la pression

## Context

L'incident du 2026-06-19 (cf. `validation.md`, post-mortem) a montré une faille
structurelle face à un **flood applicatif (L7) distribué** : ~900 req/s répartis
sur ~300 sous-réseaux /24, 56 pays, avec un User-Agent Safari iPhone légitime et
un simple `GET /`. L'origine (OpenResty + app) a été saturée (`502/500`, latence
30 s) pendant que le WAF laissait passer **99,99 %** du flood.

Deux observations clés issues des logs :

1. **Le scoring par requête est aveugle au volume.** Chaque requête, prise
   isolément, est irréprochable : UA réaliste, `GET /`, IP « neuve » (chaque /24
   n'envoie que ~88 requêtes). Le moteur de risque (ADR-015) la note `risk ~15-27`,
   très en dessous du palier `CHALLENGE` (65). Résultat : `ALLOW`.
2. **Les contrôles volumétriques sont par-IP, donc défaits par la distribution.**
   Le rate limit par IP (`429`) et le circuit-breaker par IP ne se déclenchent
   jamais : chaque IP reste sous sa limite. Le `score_below_block_threshold`
   (érosion du Trust par IP) ne touche que les rares gros émetteurs.

Après abaissement de `antiddos.global_requests_per_second` à 150, la pression
adaptative (ADR-016) a enfin escaladé (`high`/`critical`) et déclenché des blocs —
mais elle ne fait que **renforcer une contribution de risque** (poids `rate: 0.6`),
insuffisante pour soulever un flood « propre » jusqu'au palier challenge. **26 %**
du flood mitigé, **74 %** toujours transmis : l'origine reste à terre. Pendant ce
temps un humain légitime (Safari macOS) reçoit un `502` brandé par le WAF — non pas
parce qu'il est bloqué, mais parce que son origine est morte derrière un WAF qui
laisse passer le flood.

Le problème : **la pression globale est un signal trop faible et trop tardif pour
un flood L7 distribué.** Il manque un levier de **délestage (load-shedding)** qui,
sous attaque avérée, sépare les navigateurs réels (capables d'exécuter du JS) des
clients de flood (qui ne le sont pas), sans bloquer durement les humains.

## Options Evaluees

### Option A — Continuer à baisser le seuil de pression globale

- **+** Trivial (une ligne de config).
- **-** Ne corrige rien : la pression reste une contribution de risque trop faible
  pour escalader un flood « propre ». Un seuil très bas génère en plus des faux
  positifs sur les pics légitimes et reste **global** (une attaque mono-domaine
  pénalise tous les domaines).

### Option B — Blocage dur global sous pression (retour au `503`)

- **+** Protège vite l'origine.
- **-** Viole frontalement ADR-016 : faux positifs massifs, coupe le chemin de
  récupération humain. Inacceptable (le coût d'un FP humain est jugé supérieur à
  celui d'un FN, cf. requirements-detection.md).

### Option C — Augmenter fortement le poids `rate` / la contribution de pression

- **+** Reste dans le cadre du moteur de risque gradué.
- **-** Réglage instable : un poids assez fort pour escalader le flood escalade
  aussi les humains pris dans la même fenêtre. On déplace le problème de FP au lieu
  de le résoudre. Ne distingue toujours pas navigateur réel et client de flood.

### Option D — Mode « sous attaque » : challenge forcé piloté par la pression (per-domaine)

- **+** Sous pression avérée (`high`/`critical`, **évaluée par domaine**), toute
  requête **sans clearance valide** est forcée au `CHALLENGE` JS, **indépendamment
  de son risk score**. Le PoW filtre le botnet sans moteur JS ; le navigateur réel
  résout une fois, obtient un cookie, et passe ensuite sans friction.
- **+** Mitigation **réversible** (challenge, pas blocage) → conforme ADR-016 :
  l'humain récupère toujours. Les visiteurs avec cookie valide, bots vérifiés
  (FR-36) et whitelist passent sans friction.
- **+** **Évaluation par domaine** : un flood sur `status.gaetandev.fr` ne met pas
  les autres vhosts en mode sous attaque → faux positifs circonscrits.
- **+** Réutilise les briques existantes (challenge JS FR-06, PoW adaptatif FR-14)
  et le mode shadow (FR-38) pour calibrer sans appliquer.
- **-** Demande un compteur **par domaine** (coût mémoire borné par LRU) et une
  machine à états avec **hystérésis** pour éviter le battement (flapping) entre
  modes.
- **-** Les clients **non-navigateurs légitimes** (API/XHR, mobile) ne peuvent pas
  résoudre un challenge JS : ils doivent être traités à part sous attaque (ne pas
  leur servir une page JS insoluble).

## Decision

**Option D est retenue** (FR-39). Le WAF implémente un **mode « sous attaque »**,
piloté par la pression et **évalué par domaine** par défaut :

- Le WAF DOIT entrer en mode sous attaque pour un scope (domaine ou global) dès que
  sa pression atteint `under_attack.trigger_pressure` (défaut `high`).
- En mode sous attaque, toute requête **sans clearance** DOIT être forcée à au moins
  `CHALLENGE`, **indépendamment de son risk score**. Une « clearance » est :
  cookie `waf_session` valide (FR-06), bot vérifié (FR-36), IP whitelistée (FR-04),
  ou trust persistant « sticky » (FR-37).
- Une requête avec clearance DOIT continuer à passer **sans friction ajoutée**
  (récupération : un seul PoW résolu suffit ensuite).
- La mitigation reste **réversible** : aucune décision de blocage dur n'est prise
  du seul fait du mode sous attaque (conforme ADR-016).
- Le mode DOIT être **réversible avec hystérésis** : entrée à `trigger_pressure`,
  sortie seulement quand la pression retombe à `exit_pressure` (défaut `elevated`)
  pendant `cooldown` (défaut `30s`), pour éviter le battement.
- Les **clients non-navigateurs** (méthode non GET/HEAD, ou `Accept` négociant
  explicitement un type non-HTML comme `application/json`) NE DOIVENT PAS recevoir
  de challenge JS insoluble : ils restent soumis au reste de la chaîne (rate limit
  par IP, moteur de risque). La détection de navigation (FR-06) est **relâchée**
  sous attaque : un `GET`/`HEAD` sans clearance est considéré challengeable même
  sans `Accept: text/html` (un vrai navigateur l'envoie de toute façon).
- Le mode DOIT être compatible **shadow** (FR-38) : calculé et journalisé
  (`under_attack: true`) sans application, pour calibration ≥ 24 h.
- Le mode DOIT être **observable** : champ de log `under_attack`, métrique
  `waf_under_attack{domain}`, et alerte (FR-29) à l'entrée et à la sortie du mode.

Les contrôles durs restent réservés aux signaux déterministes ou locaux (blacklist,
honeypot, circuit-breaker par IP, threat-intel critique, JA3 blacklisté, rate limit
par IP `429`), inchangés.

## Consequences

- Nouvelle exigence **FR-39** dans `requirements-detection.md` (doc passé en
  `draft`, version bump). FR-08 (ADR-016) reste la base ; FR-39 ajoute le levier de
  délestage manquant.
- Le schéma de configuration ajoute le bloc `antiddos.under_attack`.
- Le détecteur de pression évolue : un compteur **par domaine** (anneau de buckets
  par domaine, nombre de domaines borné par LRU) s'ajoute au compteur global ;
  `scope` choisit lequel pilote le mode.
- Le middleware de challenge (FR-06) consomme un nouveau header interne
  `X-WAF-Under-Attack` et force le challenge en conséquence.
- L'événement de sécurité (FR-09) gagne le champ `under_attack`.
- Nouvelles métriques Prometheus `waf_under_attack{domain}` et
  `waf_under_attack_challenges_total{domain}`.
- Implémentée en Slice 12.1. L'alerte de transition (FR-29) et le traitement
  spécifique des clients non-navigateurs sous attaque (cap `THROTTLE`/`TARPIT` au
  lieu de simple laissez-passer) sont dans le périmètre ; le hot-reload du seuil par
  domaine et un sous-mode « siège » strict sont hors première tranche.

## Spec References

- [requirements.md](../requirements.md) FR-08
- [requirements-detection.md](../requirements-detection.md) FR-39 (articulation FR-06/FR-08/FR-34/FR-38)
- [features/anti-ddos.feature](../features/anti-ddos.feature)
- [schemas/config.schema.json](../schemas/config.schema.json)
- [ADR-016](ADR-016-adaptive-global-pressure.md) — pression globale adaptative (base)
- [ADR-015](ADR-015-risk-scoring-decision-engine.md) — décision graduée et réversible
