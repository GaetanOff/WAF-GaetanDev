Feature: Moteur de Règles Personnalisées
  En tant qu'administrateur du WAF,
  Je veux définir des règles métier en YAML
  Afin d'adapter le WAF à des besoins spécifiques sans modifier le code.

  # Syntaxe : specs/schemas/rule.schema.json v2.0.0. Les scénarios @deferred
  # décrivent des capacités spécifiées mais NON implémentées (audit du
  # 2026-09-24, point 2.1) : ils ne sont pas un critère d'acceptation tant que
  # leur implémentation n'est pas planifiée (specs/tasks.md, T17.x).

  Background:
    Given le WAF est configuré avec rules.enabled = true
    And les règles sont chargées depuis le fichier rules.file

  Scenario: Règle de blocage par user-agent
    Given la règle suivante est active:
      name: "block-sqlmap"
      priority: 10
      enabled: true
      conditions:
        - {field: user_agent, operator: contains, value: "sqlmap"}
      actions:
        - {type: block, value: "rule_sqlmap"}
    When une requête arrive avec User-Agent "sqlmap/1.7.2"
    Then la requête reçoit HTTP 403
    And X-WAF-Reason vaut "rule_sqlmap"

  Scenario: Conditions combinées en ET — path et pays
    Given la règle:
      name: "penalize-admin-from-highrisk"
      priority: 20
      enabled: true
      conditions:
        - {field: path, operator: starts_with, value: "/admin/"}
        - {field: country, operator: in_list, values: ["CN", "RU"]}
      actions:
        - {type: score_delta, delta: -15}
    When une requête dont CF-IPCountry est "CN", prouvé Cloudflare, arrive sur "/admin/dashboard"
    Then la règle matche et le trust score est décrémenté de 15
    When la même requête arrive sur "/public"
    Then la règle ne matche pas (toutes les conditions doivent être vraies)

  Scenario: Priorité des règles — premier match, short-circuit
    Given deux règles actives:
      - Règle A: priority=5, conditions: ip equals 1.2.3.4, action: log "trusted_partner"
      - Règle B: priority=10, conditions: user_agent contains "curl", action: block
    When une requête arrive de "1.2.3.4" avec User-Agent "curl/7.88"
    Then la Règle A (priority 5) est évaluée en premier et journalise "trusted_partner"
    And la Règle B n'est pas évaluée (short-circuit, continue=false)

  Scenario: Règle avec continue=true — plusieurs règles matchent
    Given deux règles:
      - Règle A: priority=5, conditions: path starts_with /api/, action: add_header "X-API: 1", continue: true
      - Règle B: priority=10, conditions: method equals POST, action: score_delta -5
    When une requête POST arrive sur "/api/data"
    Then la Règle A ajoute l'en-tête de réponse et l'évaluation continue
    And la Règle B décrémente le trust score de 5

  Scenario: Règle basée sur le trust_score courant
    Given la règle:
      name: "tarpit-low-trust-checkout"
      enabled: true
      conditions:
        - {field: trust_score, operator: lt, value: "25"}
        - {field: path, operator: starts_with, value: "/checkout/"}
      actions:
        - {type: tarpit}
    Given un visiteur avec trust_score = 20
    When il accède à "/checkout/payment"
    Then la requête est classée TARPIT

  Scenario: Règle non activée — ignorée
    Given une règle sans clé enabled
    When le WAF charge les règles
    Then la règle n'est ni compilée ni évaluée

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

  # ── Chargement fail-fast ────────────────────────────────────────────────────

  Scenario: Champ de condition inconnu — démarrage refusé
    Given une règle "bad-rule" avec une condition field: "unknown_field"
    When le WAF charge les règles au démarrage
    Then le démarrage échoue avec: rule "bad-rule": unsupported condition field "unknown_field"
    And aucune règle n'est chargée

  Scenario: Action non implémentée — démarrage refusé
    Given une règle "r" avec une action type: "challenge"
    When le WAF charge les règles au démarrage
    Then le démarrage échoue avec: rule "r": unsupported action type "challenge"
    # Chargée puis ignorée, l'action donnait l'illusion d'une protection.

  Scenario: add_header sans nom d'en-tête — démarrage refusé
    Given une règle "r" avec une action type: "add_header" sans clé header
    When le WAF charge les règles au démarrage
    Then le démarrage échoue avec: rule "r": add_header action requires a valid header name
    # Chargée, l'action ne posait aucun en-tête.

  Scenario: Clé inconnue — démarrage refusé
    Given une règle écrite avec "op: equals" au lieu de "operator: equals"
    When le WAF charge les règles au démarrage
    Then le démarrage échoue (décodage strict du fichier de règles)

  # ── Différés : spécifiés, non implémentés ───────────────────────────────────

  @deferred
  Scenario: Opérateurs booléens OR et NOT
    Given une règle dont les conditions sont un groupe {operator: OR, items: [...]}
    When une requête satisfait une seule des conditions du groupe
    Then la règle matche

  @deferred
  Scenario: Actions challenge, rate_limit, redirect et allow
    Given une règle d'action challenge, rate_limit(10/s), redirect(302) ou allow
    When elle matche
    Then l'action correspondante est appliquée

  @deferred
  Scenario: Métrique par règle
    When une règle matche
    Then waf_rule_matches_total{rule_name} est incrémenté

  @deferred
  Scenario: Hot-reload des règles sans redémarrage
    Given le WAF est en cours d'exécution
    When l'administrateur modifie rules.file et envoie SIGHUP
    Then les nouvelles règles sont actives sans redémarrage
    # RuleSet.Load est un échange atomique, mais aucun signal ni endpoint ne le
    # déclenche : aujourd'hui les règles sont lues au démarrage seulement.

  @deferred
  Scenario: API admin — lister les règles avec hit counts
    When GET /waf/admin/rules
    Then la réponse liste les règles avec name, priority, enabled, match_count, last_match_at

  @deferred
  Scenario: API admin — désactiver une règle sans reload
    When PATCH /waf/admin/rules/block-sqlmap avec body {"enabled": false}
    Then la règle est immédiatement désactivée

  @deferred
  Scenario: Règle temporelle — hour_of_day between
    Given une règle avec la condition {field: hour_of_day, operator: between, values: ["22", "6"]}
    When il est 23h00
    Then la règle matche
