Feature: Audit Trail des Actions Admin
  En tant qu'opérateur du WAF,
  Je veux un journal immuable de toutes les actions d'administration
  Afin de savoir qui a fait quoi et quand en cas d'incident ou d'audit de conformité.

  # Contrat d'une entrée : specs/schemas/audit-entry.schema.json
  # ({timestamp, action, target, result}, actions en minuscules) ; endpoint :
  # listAuditEntries (admin.openapi.yaml). Les scénarios @deferred sont
  # spécifiés mais NON implémentés (audit du 2026-09-24, point 2.6).

  Background:
    Given l'API admin est accessible sur le port 9090
    And audit.enabled = true
    And audit.max_entries = 10000

  Scenario: Ajout en blacklist — journalisé
    Given un admin authentifié
    When POST /waf/admin/blacklist avec {"ip": "1.2.3.4", "reason": "bot scanner"}
    Then l'action est journalisée immédiatement:
      {
        "timestamp": "<RFC 3339, UTC>",
        "action": "add_blacklist",
        "target": "1.2.3.4",
        "result": "created"
      }

  Scenario: Modification de configuration — journalisée
    When PATCH /waf/admin/config avec body modifiant rate_limit.requests_per_second
    Then une entrée action="config_patch", result="applied" est journalisée
    And sa cible liste les champs modifiés ("rate_limit.requests_per_second")

  Scenario: Reset d'un visiteur — journalisé
    When DELETE /waf/admin/visitors/{ip_hash}
    Then l'action est journalisée avec action="reset_visitor" et result="reset"

  Scenario: Effacement RGPD — journalisé avec type spécifique
    When POST /waf/admin/gdpr/erase avec l'IP du visiteur
    Then l'action est journalisée avec action="gdpr_erase" et result="erased" (distinguable des resets)

  Scenario: Consultation de l'audit trail via API
    When GET /waf/admin/audit?page=1&limit=50
    Then la réponse liste au plus 50 entrées, de la plus ancienne à la plus récente
    And chaque entrée est conforme à audit-entry.schema.json

  Scenario: Audit trail append-only — pas de suppression via API
    When DELETE /waf/admin/audit est appelé
    Then HTTP 405 Method Not Allowed est retourné
    And l'audit trail est intact

  Scenario: Rotation FIFO quand la limite est atteinte
    Given 10 000 entrées d'audit sont en mémoire (limite)
    When une nouvelle action admin est effectuée (entrée 10 001)
    Then la plus ancienne entrée est supprimée (FIFO)
    And la nouvelle entrée est ajoutée
    And le nombre total reste 10 000

  Scenario: Export de l'audit trail vers fichier (option)
    Given audit.file = "/var/log/waf/audit.jsonl"
    When une action admin est effectuée
    Then l'entrée est écrite dans le fichier en format JSON-lines
    And le fichier est ouvert en mode append
    And le fichier est créé avec les permissions 0600 (lisible par le seul propriétaire)

  Scenario: Aucun secret dans l'audit trail
    When une action admin est journalisée
    Then aucune valeur de configuration n'est journalisée, seulement des noms de champs
    And une cible ressemblant à un secret (token, secret, password, api_key) est remplacée par "***"

  # ── Différés : spécifiés, non implémentés ───────────────────────────────────

  @deferred
  Scenario: Filtrage par date
    When GET /waf/admin/audit?since=2026-06-03T00:00:00Z&until=2026-06-03T23:59:59Z
    Then seules les entrées dans cette plage temporelle sont retournées
    # FR-27 exige ?since= : ni since ni until ne sont acceptés aujourd'hui.

  @deferred
  Scenario: Filtrage par action
    When GET /waf/admin/audit?action=add_blacklist
    Then seules les entrées avec action="add_blacklist" sont retournées

  @deferred
  Scenario: Échec d'authentification — journalisé
    Given une requête admin avec un token invalide
    When l'authentification échoue
    Then l'échec est journalisé avec action="auth_failed" et l'IP cliente
    # Aujourd'hui : l'échec est compté par l'anti-brute-force (FR-30), pas journalisé.

  @deferred
  Scenario: Désactivation d'une règle — journalisée
    When PATCH /waf/admin/rules/block-sqlmap avec {"enabled": false}
    Then l'action est journalisée avec action="rule_disabled"
    # Dépend de /waf/admin/rules, lui-même différé (rules-engine.feature).

  @deferred
  Scenario: Contexte de requête dans l'entrée d'audit
    When une action admin est journalisée
    Then l'entrée porte aussi endpoint, méthode, statut de réponse, IP cliente, et pour config_patch l'ancienne et la nouvelle valeur
