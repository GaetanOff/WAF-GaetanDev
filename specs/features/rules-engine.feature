Feature: Moteur de Règles Personnalisées
  En tant qu'administrateur du WAF,
  Je veux définir des règles métier complexes en YAML
  Afin d'adapter le WAF à des besoins spécifiques sans modifier le code.

  Background:
    Given le WAF est configuré avec rules_engine.enabled = true
    And les règles sont chargées depuis configs/rules.yaml

  Scenario: Règle de blocage par user-agent — match exact
    Given la règle suivante est active:
      name: "block-sqlmap"
      priority: 10
      conditions:
        operator: OR
        items:
          - field: user_agent, op: contains, value: "sqlmap"
          - field: user_agent, op: contains, value: "nikto"
      actions:
        - type: block, params: {status: 403}
    When une requête arrive avec User-Agent "sqlmap/1.7.2"
    Then la règle "block-sqlmap" est matchée
    And la requête reçoit HTTP 403
    And waf_rule_matches_total{rule_name="block-sqlmap"} est incrémenté

  Scenario: Règle combinant path ET pays (AND)
    Given la règle:
      name: "challenge-sensitive-from-highrisks"
      priority: 20
      conditions:
        operator: AND
        items:
          - field: path, op: starts_with, value: "/admin/"
          - field: country, op: in_list, value: ["CN", "RU"]
      actions:
        - type: challenge
        - type: score_delta, params: {value: -15}
    When une requête de Chine arrive sur "/admin/dashboard"
    Then la règle matche
    And le challenge JS est déclenché
    And le trust score est décrémenté de 15

  Scenario: Règle avec opérateur NOT
    Given la règle:
      name: "allow-internal-only"
      conditions:
        operator: NOT
        items:
          - field: ip_cidr, op: in_cidr, value: "10.0.0.0/8"
      actions:
        - type: block
    When une requête arrive de "8.8.8.8" (non interne)
    Then la règle matche (NOT IN 10.0.0.0/8 → vrai)
    And la requête est bloquée

  Scenario: Priorité des règles — règle de plus haute priorité évaluée en premier
    Given deux règles actives:
      - Règle A: priority=5, conditions: ip=1.2.3.4, action: allow
      - Règle B: priority=10, conditions: user_agent contains "curl", action: block
    When une requête arrive de "1.2.3.4" avec User-Agent "curl/7.88"
    Then la Règle A (priority 5) est évaluée en premier
    And l'action "allow" est exécutée
    And la Règle B n'est pas évaluée (short-circuit, continue=false)

  Scenario: Règle avec continue=true — plusieurs règles matchent
    Given deux règles avec continue=true:
      - Règle A: priority=5, conditions: country=US, action: add_header "X-Country: US", continue: true
      - Règle B: priority=10, conditions: path starts_with /api/, action: rate_limit(10/s)
    When une requête US arrive sur "/api/data"
    Then la Règle A matche et ajoute le header (continue → évalue suivante)
    And la Règle B matche et applique le rate limit
    And les deux actions sont exécutées

  Scenario: Règle basée sur le trust_score courant
    Given la règle:
      name: "extra-challenge-low-trust"
      conditions:
        operator: AND
        items:
          - field: trust_score, op: lt, value: 25
          - field: path, op: starts_with, value: "/checkout/"
      actions:
        - type: challenge
    Given un visiteur avec trust_score = 20
    When il accède à "/checkout/payment"
    Then la règle matche et le challenge est déclenché

  # ── Résolution de l'IP de règle ──────────────────────────────────────────────

  Scenario: Règle de blocage par CIDR — X-Real-IP forgé n'y échappe pas
    Given une règle bloque la condition ip in_cidr ["10.0.0.0/8"]
    And un client se connecte réellement depuis "10.1.2.3"
    When il envoie une requête avec l'en-tête "X-Real-IP: 8.8.8.8"
    Then la règle matche quand même et la requête reçoit HTTP 403
    # X-Real-IP traverse Cloudflare sans être réécrit : s'il pilotait la
    # résolution, toute règle de blocage par IP serait contournable.

  Scenario: Usurpation d'une IP de confiance via X-Real-IP
    Given une règle accorde un score_delta positif à ip equals "203.0.113.7"
    And un client se connecte réellement depuis "8.8.8.8"
    When il envoie une requête avec l'en-tête "X-Real-IP: 203.0.113.7"
    Then la règle ne matche pas et aucun bonus de score n'est accordé

  Scenario: Derrière Cloudflare — l'IP de règle est celle de CF-Connecting-IP validée
    Given cloudflare.trusted = true
    And la connexion provient d'une plage Cloudflare avec "CF-Connecting-IP: 10.1.2.3"
    And une règle bloque la condition ip in_cidr ["10.0.0.0/8"]
    When la requête est évaluée
    Then la règle matche sur "10.1.2.3", l'IP réelle établie par le WAF
    # Même résolution que la whitelist, la blacklist, le rate limit et le trust
    # score : un seul chemin d'IP pour toutes les décisions.

  Scenario: Hot-reload des règles sans redémarrage
    Given le WAF est en cours d'exécution
    When l'administrateur modifie configs/rules.yaml et envoie SIGHUP
    Then dans les 100ms, les nouvelles règles sont actives
    And les règles en cours d'évaluation sur les requêtes existantes ne sont pas interrompues

  Scenario: API admin — lister les règles avec hit counts
    When GET /waf/admin/rules
    Then la réponse liste toutes les règles actives avec:
      | name           | nom de la règle  |
      | priority       | priorité         |
      | enabled        | true/false       |
      | match_count    | nombre de matchs |
      | last_match_at  | dernier match    |

  Scenario: API admin — désactiver une règle sans reload
    When PATCH /waf/admin/rules/block-sqlmap avec body {"enabled": false}
    Then la règle est immédiatement désactivée
    And les requêtes sqlmap ne sont plus bloquées par cette règle

  Scenario: Règle invalide — compilation échoue avec message clair
    Given une règle avec un champ "field" inconnu: "unknown_field"
    When le WAF charge les règles au démarrage
    Then le démarrage échoue avec un message d'erreur: "règle 'bad-rule': champ inconnu 'unknown_field'"
    And aucune règle n'est chargée (fail-fast)

  Scenario: Règle temporelle — active seulement la nuit
    Given la règle:
      name: "strict-night-protection"
      conditions:
        operator: AND
        items:
          - field: hour_of_day, op: between, value: [22, 6]
          - field: trust_score, op: lt, value: 60
      actions:
        - type: challenge
    When il est 23h00 et un visiteur score=55 envoie une requête
    Then la règle matche et le challenge est déclenché
    When il est 14h00 le lendemain
    Then la règle ne matche pas (hors plage horaire)
