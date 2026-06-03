Feature: Audit Trail des Actions Admin
  En tant qu'opérateur du WAF,
  Je veux un journal immuable de toutes les actions d'administration
  Afin de savoir qui a fait quoi et quand en cas d'incident ou d'audit de conformité.

  Background:
    Given l'API admin est accessible sur le port 9090
    And audit.enabled = true
    And audit.max_entries = 10000

  Scenario: Ajout en blacklist — journalisé
    Given un admin authentifié
    When POST /waf/admin/blacklist avec {"ip": "1.2.3.4", "reason": "bot scanner"}
    Then l'action est journalisée immédiatement:
      {
        "timestamp": "<ISO8601>",
        "action": "BLACKLIST_ADD",
        "endpoint": "/waf/admin/blacklist",
        "method": "POST",
        "request_body": {"ip": "1.2.3.4", "reason": "bot scanner"},
        "response_status": 201,
        "client_ip": "<IP de l'admin>"
      }

  Scenario: Modification de configuration — journalisée
    When PATCH /waf/admin/config avec body modifiant rate_limit.requests_per_second
    Then l'action est journalisée avec l'ancien et le nouveau paramètre

  Scenario: Désactivation d'une règle — journalisée
    When PATCH /waf/admin/rules/block-sqlmap avec {"enabled": false}
    Then l'action est journalisée avec action="RULE_DISABLED" et rule_name="block-sqlmap"

  Scenario: Reset d'un visiteur — journalisé
    When DELETE /waf/admin/visitors/{ip_hash}
    Then l'action est journalisée avec action="VISITOR_RESET"

  Scenario: Effacement RGPD — journalisé avec type spécifique
    When DELETE /waf/admin/visitors/{ip_hash} (marqué comme effacement RGPD)
    Then l'action est journalisée avec action="GDPR_ERASURE" (distinguable des resets normaux)

  Scenario: Échec d'authentification — journalisé
    Given une requête admin avec un token invalide
    When l'authentification échoue
    Then l'échec est journalisé avec action="AUTH_FAILED" et le client_ip

  Scenario: Consultation de l'audit trail via API
    When GET /waf/admin/audit?limit=50
    Then la réponse liste les 50 dernières entrées d'audit
    And chaque entrée est conforme au schéma audit trail

  Scenario: Filtrage par date
    When GET /waf/admin/audit?since=2026-06-03T00:00:00Z&until=2026-06-03T23:59:59Z
    Then seules les entrées dans cette plage temporelle sont retournées

  Scenario: Filtrage par action
    When GET /waf/admin/audit?action=BLACKLIST_ADD
    Then seules les entrées avec action="BLACKLIST_ADD" sont retournées

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
    Given audit.file_path = "/var/log/waf/audit.jsonl"
    When une action admin est effectuée
    Then l'entrée est écrite dans le fichier en format JSON-lines
    And le fichier est ouvert en mode append
    And les permissions du fichier sont 0640 (non lisible par autres)

  Scenario: Secrets masqués dans l'audit trail
    Given un admin modifie challenge.secret_key via PATCH /waf/admin/config
    When l'action est journalisée
    Then le nouveau secret_key est masqué (remplacé par "***") dans l'audit
    And aucun secret n'apparaît en clair dans l'audit trail
