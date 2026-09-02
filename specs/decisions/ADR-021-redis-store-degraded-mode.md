---
status: accepted
date: 2026-09-02
deciders: GaetanDev
relates-to: ADR-002 (backend de stockage), requirements.md (NFR-01, NFR-02), requirements-advanced.md (FR-20), features/storage-backend.feature
---

# ADR-021 — Sémantique du backend Redis : écriture traversante et mode dégradé

## Context

ADR-002 a tranché « in-memory par défaut, Redis optionnel » et annonçait
`internal/storage/redis/store.go`. Ce fichier n'a jamais existé :
`storage.backend: redis` était accepté par la validation, puis **ignoré** —
`cmd/waf/main.go` instanciait inconditionnellement `memory.New(...)`. Un
opérateur qui lisait « stockage persistant partagé entre instances » dans
`CONFIG.md` obtenait un état par nœud, sans le savoir. C'est cette promesse
qu'il faut honorer.

Deux contraintes se contredisent :

- **NFR-01** : latence ajoutée P50 < 1 ms. `GetVisitor` est appelé **plusieurs
  fois par requête** (score, challenge, moteur de risque). Un aller-retour
  réseau de 100–500 µs par appel consomme le budget entier.
- **FR-20** : « en cas de perte de Redis, chaque nœud DOIT continuer à
  fonctionner de manière autonome (dégradé mais opérationnel) ».

S'ajoute une contrainte de forme : `storage.Store` ne retourne **aucune erreur**
(`GetVisitor(key) (*VisitorState, bool)`). Une implémentation réseau doit donc
décider seule quoi faire d'une erreur Redis — elle ne peut pas la remonter.

## Options Évaluées

### Option A — Redis pur (source de vérité unique, aucun état local)

- **Pour** : cohérence maximale, un seul état pour tout le cluster.
- **Contre** : chaque lecture est un aller-retour réseau ; sur perte de Redis,
  le WAF perd tout scoring (tout visiteur redevient neuf) — violation directe
  de FR-20. Une saturation Redis devient une panne WAF.

### Option B — Redis + cache local de lecture avec TTL court

- **Pour** : amortit les lectures répétées d'une même requête.
- **Contre** : un TTL de cache introduit une fenêtre d'incohérence *silencieuse*
  entre nœuds sur une décision de sécurité (un visiteur banni sur un nœud reste
  accepté ailleurs pendant le TTL). Le cache masque aussi la panne : impossible
  de distinguer « Redis répond » de « Redis muet mais cache chaud ».

### Option C — Écriture traversante + repli local explicite sur panne

- Nominal : Redis est la source de vérité. Les lectures viennent de Redis. Les
  écritures vont dans Redis **et** dans un `memory.Store` local (traversant).
- Dégradé : après N erreurs Redis consécutives, le nœud sert **tout** depuis son
  store local pendant une fenêtre courte, puis re-sonde Redis. Transition
  journalisée et exposée en métrique.
- **Pour** : honore FR-20 sans fenêtre d'incohérence cachée — le mode dégradé
  est un état observable, pas une dégradation invisible. L'écriture traversante
  garantit qu'un basculement hérite d'un état local récent au lieu de repartir
  de zéro.
- **Contre** : chaque écriture est faite deux fois (une écriture mémoire ≈ 100 ns
  face à un aller-retour Redis : coût négligeable) ; l'état local peut diverger
  du cluster pendant la panne — accepté, c'est la définition de l'eventual
  consistency retenue par FR-20.

## Decision

**Option C.**

- Clés : `waf:visitor:<key>` et `waf:bucket:<key>`, valeurs en JSON des structures
  `storage.VisitorState` / `storage.RateBucket`.
- TTL Redis dérivé de `ExpiresAt` (`EXPIRE` à l'écriture) : l'expiration est
  déléguée à Redis, il n'y a pas de goroutine de nettoyage côté WAF. Un
  `ExpiresAt` nul écrit une clé sans TTL — cas qui n'existe pas en pratique (le
  score manager et le rate limiter posent toujours une échéance).
- **Éviction** : l'éviction LRU bornée par `trust.max_visitors` ne s'applique
  **qu'au store local**. Côté Redis, la borne mémoire est la politique
  `maxmemory-policy` de l'instance Redis, hors du périmètre du WAF — documenté
  dans `CONFIG.md`, car c'est une différence de comportement réelle entre les
  deux backends.
- **Timeout par opération** : `storage.redis.timeout` (défaut `100ms`). Une
  opération lente est un échec : elle compte pour le passage en dégradé plutôt
  que de bloquer le chemin de requête.
- **Bascule** : 3 erreurs consécutives → dégradé pour 5 s, puis une opération de
  sonde. Un succès en nominal remet le compteur à zéro. Constantes internes
  (`degradedThreshold`, `degradedWindow`), pas des clés de configuration : ce
  sont des détails de résilience, pas une politique d'exploitation.
- **Démarrage** : un `PING` est exigé au démarrage (budget 5 s). Redis
  injoignable au boot est une **erreur de démarrage**, pas un mode dégradé :
  l'opérateur a demandé Redis, une adresse fautive ou un mot de passe erroné
  doit se voir immédiatement. Une perte **après** le boot est un mode dégradé.
- `ListVisitors` (API admin) parcourt les clés par `SCAN` borné à
  `trust.max_visitors` entrées : jamais de `KEYS` sur un Redis de production.

## Consequences

- `internal/storage/redis/store.go` implémente `storage.Store` ; `cmd/waf`
  sélectionne l'implémentation via `storage.backend` (fin du no-op silencieux).
- Le paquet dialogue avec Redis à travers une interface réduite aux commandes
  réellement utilisées (`Get`, `Set`, `Del`, `Scan`, `Ping`, `Close`), ce qui
  permet de tester le mode dégradé, le calcul de TTL et la sérialisation
  **sans Redis en CI** (ADR-002 : les tests d'intégration n'exigent pas Redis).
- Métriques ajoutées : `waf_storage_degraded` (jauge 0/1) et
  `waf_storage_errors_total{operation}`. Sans elles, le mode dégradé serait le
  genre d'état invisible que cet ADR cherche justement à éliminer.
- Différence assumée entre backends : `memory` borne le nombre de visiteurs,
  `redis` borne la mémoire côté serveur Redis. Le WAF ne tente pas d'émuler la
  LRU dans Redis (ce serait un compteur global contesté à chaque requête).
- `cluster.enabled` (FR-20, Pub/Sub) reste **indépendant** du backend : le bus
  d'événements et le store partagé sont deux mécanismes distincts qui utilisent
  la même connexion configurée `storage.redis`.

## Spec References

- [ADR-002](ADR-002-storage-backend.md) — décision d'origine (in-memory par défaut, Redis optionnel)
- [requirements.md](../requirements.md) — NFR-01 (performance), NFR-02 (fiabilité)
- [requirements-advanced.md](../requirements-advanced.md) — FR-20 (état distribué, fonctionnement autonome sur perte de Redis)
- [features/storage-backend.feature](../features/storage-backend.feature)
- [schemas/config.schema.json](../schemas/config.schema.json) — `storage.backend`, `storage.redis.*`
