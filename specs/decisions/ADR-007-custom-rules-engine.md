---
status: accepted
date: 2026-06-03
deciders: GaetanDev
---

# ADR-007 — Moteur de Règles Personnalisées

## Context

Les WAFs enterprise (Cloudflare, AWS WAF, ModSecurity) offrent un langage de règles permettant aux opérateurs de définir des comportements fins sans modifier le code. Sans rules engine, toute règle métier spécifique nécessite un redémarrage et une modification du code.

## Options

### Option A — ModSecurity CRS (Core Rule Set)
Bibliothèque mature, règles OWASP intégrées. Problème : implémentation C via CGO, poids lourd, complexité opérationnelle.

### Option B — Lua scripting (comme nginx/OpenResty)
Flexible, scripté. Problème : runtime Lua à embarquer, sandbox sécurité complexe, performances variables.

### Option C — DSL YAML compilé à la volée en Go (retenu)
Règles YAML déclaratives. Chargées et compilées en structures Go au démarrage/hot-reload. Évaluation par un moteur natif Go. Zéro interprétation dynamique par requête.

## Design du DSL YAML

```yaml
rules:
  - name: "block-scanner-tools"
    priority: 10
    enabled: true
    conditions:
      operator: OR
      items:
        - field: user_agent
          op: contains
          value: "sqlmap"
        - field: user_agent
          op: contains
          value: "nikto"
        - field: user_agent
          op: contains
          value: "nmap"
    actions:
      - type: block
        params:
          status: 403
          message: "Forbidden"
      - type: log
        params:
          level: warn
          message: "Scanner tool detected"

  - name: "rate-limit-api-from-datacenter"
    priority: 20
    enabled: true
    conditions:
      operator: AND
      items:
        - field: path
          op: starts_with
          value: "/api/"
        - field: asn_type
          op: equals
          value: "hosting"
    actions:
      - type: rate_limit
        params:
          requests_per_second: 5
          burst: 10

  - name: "geo-block-high-risk"
    priority: 5
    enabled: true
    conditions:
      operator: AND
      items:
        - field: country
          op: in_list
          value: ["CN", "RU", "KP", "IR"]
        - field: trust_score
          op: lt
          value: 40
    actions:
      - type: challenge
      - type: score_delta
        params:
          value: -10
```

## Architecture interne

```
YAML config
    │
    ▼
RuleCompiler.Compile() → []CompiledRule
    │
    ▼ (au démarrage / hot-reload)
RuleEngine (slice de CompiledRule triée par priority)
    │
    ▼ (par requête, dans middleware)
RuleEngine.Evaluate(ctx RequestContext) []Action
    │
    ▼
ActionExecutor.Execute(actions, w, r)
```

**CompiledRule** : struct Go avec les conditions pré-compilées (regex compilées, CIDR parsés, listes en maps). L'évaluation par requête ne fait aucune compilation.

**RequestContext** : struct Go passée au moteur avec tous les champs accessibles (ip, ua, path, method, country, ja3, trust_score, behavioral_score, headers map).

## Performance

Pour 100 règles, l'évaluation worst-case (toutes les règles évaluées, chaque condition évaluée) est O(R×C) où R = nombre de règles, C = conditions moyennes par règle. Avec R=100, C=3 : 300 comparaisons simples, toutes < 1 µs au total.

Les regex compilées et les maps de lookup garantissent des évaluations O(1) pour les conditions `in_list`.

## Hot-Reload

1. SIGHUP ou `PATCH /waf/admin/config` → watcher déclenché
2. Nouveau fichier YAML chargé en mémoire
3. `RuleCompiler.Compile()` appelé → nouvel engine
4. `atomic.Value.Store(newEngine)` → swap atomique
5. Les requêtes en cours continuent avec l'ancien engine, les nouvelles utilisent le nouvel engine
6. Zéro downtime, zéro lock de longue durée

## Conséquences

- Nouveau package `internal/rules/`
  - `compiler.go` : parsing YAML + compilation en structs Go
  - `engine.go` : évaluation, retourne slice d'actions
  - `actions.go` : executeurs d'actions
  - `context.go` : struct RequestContext
- Nouveau schéma `specs/schemas/rule.schema.json`
- `internal/middleware/rules/middleware.go` : intégration dans le pipeline
- Métriques : `waf_rule_matches_total{rule_name}`, `waf_rule_eval_duration_seconds`
- API admin : `GET/POST/DELETE /waf/admin/rules`

## Spec References

- [requirements-advanced.md](../requirements-advanced.md) FR-17
- [schemas/rule.schema.json](../schemas/rule.schema.json)
