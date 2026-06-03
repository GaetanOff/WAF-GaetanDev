---
status: accepted
date: 2026-06-03
deciders: GaetanDev
---

# ADR-004 — Approche fingerprinting navigateur

## Context

Le fingerprinting navigateur est utilisé pour : (1) lier un cookie de session à un "profil navigateur" et détecter les tentatives de réutilisation du cookie depuis un autre environnement, (2) contribuer au score anti-bot en détectant les signatures headless browser.

## Privacy Considerations

Le fingerprinting ne doit pas être utilisé comme tracking cross-site. Il doit uniquement servir à la sécurité dans le contexte de la session WAF. Les données collectées sont :
- Hashées SHA-256 avant stockage (non réversibles)
- Associées à un domaine unique (pas de fingerprint partagé entre domaines)
- Stockées avec un TTL court (1h par défaut)

## Signaux retenus et leur pertinence anti-bot

| Signal | Pertinence | Raison |
|--------|-----------|--------|
| User-Agent | Élevée | Headless Chrome a des UAs caractéristiques |
| Timezone offset | Moyenne | Bots souvent en UTC, écart avec langue navigateur |
| Navigator.language | Moyenne | Bots headless : souvent `en-US` avec timezone UTC |
| Screen resolution | Moyenne | Headless : résolution par défaut ou irréaliste |
| hardwareConcurrency | Faible | Facile à falsifier mais utile en combinaison |
| maxTouchPoints | Moyenne | Headless : 0 (même sur mobile emulé) |
| Canvas fingerprint | Élevée | GPU/pilote graphique unique, headless diffère |
| WebGL renderer | Élevée | Headless : SwiftShader ou llvmpipe (signatures connues) |
| Plugins count | Faible | Headless : 0 plugins, humain : variable |

## Signatures headless connues (blocage direct)

Les valeurs WebGL renderer suivantes déclenchent un score -30 :
- `Google SwiftShader` (Puppeteer/Playwright sans GPU)
- `ANGLE (Default, SwiftShader)`
- `llvmpipe` (Linux headless)
- `Mesa/X.org` (certains environnements CI)

Les User-Agent patterns suivants déclenchent un score -30 :
- `HeadlessChrome`
- `PhantomJS`
- `SlimerJS`
- `Nightmare`
- `Selenium`

## Stockage et utilisation

Le fingerprint hash est stocké dans :
1. Le payload du cookie de session (pour validation future)
2. Le `VisitorState` en mémoire (pour analyse comportementale)

**Cohérence du cookie** : à chaque requête avec cookie valide, si le fingerprint recalculé (via un header dédié ou re-challenge silencieux) diffère significativement du fingerprint enregistré, le score est décrémenté (-15) et un re-challenge est déclenché.

**Note** : le fingerprint n'est PAS recalculé à chaque requête (coût JS trop élevé). Il est calculé uniquement lors du challenge initial et stocké dans le cookie.

## Consequences

- `internal/fingerprint/fingerprint.go` : parsing des signaux reçus depuis le JS, validation des plages acceptables, calcul du hash final
- Le fingerprint hash est intégré dans le payload du cookie
- Les signatures headless sont définies dans `internal/middleware/antibot/rules.go` comme liste configurable
- Aucune donnée brute de fingerprint n'est loggée (seulement le hash)

## Spec References

- [requirements.md](../requirements.md) FR-07 (Anti-Bot), FR-06 (Challenge JS)
- [ADR-003](ADR-003-js-challenge-strategy.md) — Stratégie challenge JS
