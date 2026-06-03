---
status: accepted
date: 2026-06-03
deciders: GaetanDev
---

# ADR-009 — Behavioral Sequence Analysis

## Context

Un bot peut parfaitement passer le challenge JS, avoir un user-agent valide, et des headers corrects — et pourtant se comporter comme un scraper. L'analyse comportementale analyse les patterns de navigation sur la durée pour détecter ce que les autres couches ne voient pas.

## Signaux comportementaux retenus

### Signal 1 — Uniformité temporelle (entropie des intervalles)
Les humains ont des intervalles variables (lecture, scroll, hésitation). Les bots ont des intervalles uniformes (boucle `for` avec `sleep(N)`).

**Calcul** : écart-type des N derniers intervalles entre requêtes.
- Humain typique : std_dev > 2000 ms
- Bot rapide : std_dev < 200 ms → anomaly += 30
- Bot lent (mimétisme) : std_dev 200-800 ms → anomaly += 15

### Signal 2 — Répétition de paths
Un humain ne recharge pas 50 fois la même page.

**Calcul** : `max_repeat_count / total_requests` dans la fenêtre.
- Ratio > 0.3 (même path > 30% des req) → anomaly += 20
- Même path > 10 fois consécutives → anomaly += 40

### Signal 3 — Page velocity (vélocité de découverte)
Un humain découvre < 5 pages uniques par minute. Un crawler : > 30.

**Calcul** : distinct paths dans les 60 dernières secondes.
- > 30 paths uniques/min → anomaly += 35
- > 60 paths uniques/min → anomaly += 60

### Signal 4 — Ordre alphabétique (crawler pattern)
Les scrapers naïfs itèrent sur des listes triées.

**Détection** : séquence de 5 paths consécutifs triés alphabétiquement → anomaly += 25

### Signal 5 — Absence d'assets (headless sans rendering)
Une vraie page HTML charge CSS, JS, fonts, images. Un crawler ne charge que le HTML.

**Détection** : ratio `html_requests / asset_requests` sur 20 dernières requêtes.
- HTML > 80% (presque pas d'assets) → anomaly += 20

Note : ce signal n'est fiable que si le site charge des assets depuis le même domaine. Si assets viennent d'un CDN tiers, ratio toujours élevé même pour les humains → ce signal est pondéré dynamiquement selon la config du domaine.

### Signal 6 — Navigation depth jump (accès direct aux pages profondes)
Un humain commence par l'accueil, puis navigue. Un scraper connaît déjà l'URL cible.

**Détection** : première requête vers `/products/detail/12345/buy?ref=xyz` sans référer home → anomaly += 10
(Contribue peu car les liens directs sont courants pour les humains aussi)

## Calcul du Behavioral Anomaly Score

```
anomaly_score = min(100, sum(signal_values × weights))

Weights (ajustables via config):
  time_uniformity:  0.30
  path_repetition:  0.25
  page_velocity:    0.25
  alpha_order:      0.10
  asset_absence:    0.10
```

Si `anomaly_score > 70` : Trust Score delta = -20 (appliqué à la prochaine requête)
Si `anomaly_score > 90` : Trust Score delta = -40

## Architecture — Asynchronisme total

L'analyse comportementale **ne doit pas bloquer** le pipeline de requêtes.

```
Requête ──▶ [Pipeline WAF rapide] ──▶ Upstream
              │
              ▼ (goroutine non-bloquante via channel buffered 1000)
           [BehaviorAnalyzer.Process(event)]
              │
              ▼
           Calcul des signaux
              │
              ▼
           [TrustScore.ApplyAsync(delta)] ──▶ Appliqué à la requête SUIVANTE
```

Le channel buffered absorbe les pics. Si plein (> 1000 events en attente), les nouveaux events sont dropped silencieusement (mieux que de bloquer la requête).

## Fenêtre temporelle

L'historique des requêtes est stocké dans un **ring buffer** par visiteur (taille configurable, défaut: 50 entrées).

Structure `RequestEvent` stockée :
```go
type RequestEvent struct {
    Timestamp time.Time
    Path      string
    Method    string
    IsAsset   bool  // CSS/JS/image/font
}
```

Chaque `RequestEvent` : ~100 bytes × 50 entrées = 5 KB par visiteur.
Pour 100 000 visiteurs : 500 MB → configurable, défaut 10 000 visiteurs avec historique comportemental.

## Conséquences

- `internal/behavioral/` :
  - `analyzer.go` : calcul des 6 signaux + score
  - `ringbuffer.go` : ring buffer d'events par visiteur
  - `signals.go` : fonctions de calcul par signal
  - `worker.go` : goroutine worker consommant le channel d'events
- `VisitorProfile` étendu avec `BehaviorScore int` et ring buffer ref
- Config : `behavioral.enabled`, `behavioral.window_size`, `behavioral.signal_weights`
- Métriques : `waf_behavioral_score_histogram`, `waf_behavioral_triggers_total{signal}`

## Spec References

- [requirements-advanced.md](../requirements-advanced.md) FR-12, NFR-07
- [features/behavioral-analysis.feature](../features/behavioral-analysis.feature)
