---
status: accepted
date: 2026-06-03
deciders: GaetanDev
---

# ADR-010 — Adaptive PoW Difficulty

## Context

Durant une attaque DDoS de bots qui peuvent exécuter JavaScript, une difficulté fixe peut être trivialement parallélisée sur GPU. L'adaptation dynamique de la difficulté rend les attaques progressivement plus coûteuses à mesure qu'elles s'intensifient, sans impact sur les visiteurs légitimes en temps normal.

## Modèle de détection d'attaque

Le WAF mesure en continu un **Attack Intensity Indicator (AII)** :

```
AII = (req/s_current / req/s_baseline) × 100

Où req/s_baseline = média exponentielle mobile des dernières 24h en période calme
```

Si aucune baseline n'est disponible (premier démarrage) → utiliser le double de `rate_limit.requests_per_second` comme proxy.

**Niveaux d'attaque :**

| AII | Niveau | Description |
|-----|--------|-------------|
| < 110% | Normal | Trafic nominal |
| 110-150% | Elevated | Légère augmentation |
| 150-200% | High | Attaque probable |
| > 200% | Critical | Attaque DDoS active |

## Courbe de difficulté

```
effective_difficulty = base_difficulty + attack_bonus

base_difficulty = config.challenge.pow_difficulty  (défaut: 16)

attack_bonus:
  Normal:   0 bits
  Elevated: +2 bits   (2x plus long : ~2s)
  High:     +4 bits   (4x plus long : ~4s)
  Critical: +8 bits   (16x plus long : max ~16s)

Cap: max_difficulty = config.challenge.pow_max_difficulty (défaut: 24)
```

**Impact sur les visiteurs légitimes :**
- Niveau Normal : challenge ~500ms (unchanged)
- Niveau Critical : challenge ~8-16s (acceptable, rare, attaque active)

## Retour à la normale — Décroissance exponentielle

Quand l'attaque se calme (AII redescend), la difficulté revient progressivement :

```
effective_difficulty = attack_bonus × e^(-t/τ) + base_difficulty

τ = 300s (5 minutes) — constante de temps configurable
```

Pas de retour brusque (évite l'oscillation si l'attaque est intermittente).

## Difficulté encodée dans le token

Le token de challenge inclut la difficulté requise dans son payload signé :

```
token_payload = {
    "nonce": "<random>",
    "ip_hash": "<hash>",
    "domain": "<domain>",
    "difficulty": 18,        ← inclus dans le HMAC
    "issued_at": 1748880000,
    "expires_at": 1748880030
}
```

La vérification côté serveur utilise la difficulté du token (pas la difficulté courante) pour éviter les races entre génération et vérification. Elle vérifie aussi que `token_difficulty >= current_difficulty × 0.8` pour détecter les tentatives de rétrogradation.

## UI Adaptative

La page de challenge affiche un message différent selon le niveau :
- Normal : "Checking your browser…"
- Elevated : "Performing security verification…"
- Critical : "Enhanced security check in progress…"

Le message est injecté via le template Go (pas de changement JS côté client).

## Conséquences

- `internal/adaptive/detector.go` : calcul AII, gestion baseline EMA
- `internal/adaptive/difficulty.go` : fonction `CurrentDifficulty() int`
- `internal/middleware/challenge/nonce.go` : encode difficulté dans le token
- `web/challenge.html` : messages adaptatifs via `{{.Message}}`
- Config : `challenge.pow_max_difficulty`, `adaptive.decay_tau_seconds`
- Métriques : `waf_challenge_pow_difficulty` (gauge), `waf_attack_intensity_indicator`

## Spec References

- [requirements-advanced.md](../requirements-advanced.md) FR-14
- [ADR-003](ADR-003-js-challenge-strategy.md) — Stratégie challenge JS (base)
