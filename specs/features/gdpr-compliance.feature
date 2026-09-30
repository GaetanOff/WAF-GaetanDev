Feature: Conformité GDPR & Privacy
  En tant qu'opérateur du WAF,
  Je veux traiter les données personnelles de manière conforme au RGPD
  Afin d'être en règle légalement et de protéger la vie privée des visiteurs.

  # Contrat : FR-28 (requirements-ops.md), bloc gdpr de config.schema.json.
  # Les scénarios @deferred sont spécifiés mais NON implémentés (audit du
  # 2026-09-30) : ils ne sont pas un critère d'acceptation.

  # ── Rétention des données ───────────────────────────────────────────────────

  Scenario: VisitorState purgé après trust.score_ttl
    Given trust.score_ttl = "1h"
    And un visiteur avec IP "1.2.3.4" n'a plus envoyé de requête depuis plus d'1 heure
    When la purge du store s'exécute
    Then l'entrée VisitorState de ce visiteur est supprimée
    And la prochaine requête de cette IP crée une nouvelle entrée (score = 50)

  Scenario: Security events au-delà de 24 h non servis
    Given des security events vieux de 25 heures sont en mémoire
    When GET /waf/admin/events est appelé
    Then ces events ne sont pas dans la réponse

  Scenario: Données toujours présentes pendant la période de rétention
    Given trust.score_ttl = "1h"
    And un visiteur a été actif il y a 30 minutes
    When la purge du store s'exécute
    Then l'entrée de ce visiteur est conservée
    And son score de confiance est préservé

  @deferred
  Scenario: Durées de rétention configurables et purge par âge
    Given privacy.data_retention_hours = 24
    And privacy.event_retention_hours = 24
    When la goroutine de purge s'exécute (tick toutes les 15 min)
    Then les VisitorState inactifs depuis plus de 24 h sont supprimés
    And les security events de plus de 24 h sont effacés de la mémoire

  # ── IP Anonymisation ────────────────────────────────────────────────────────

  Scenario: Anonymisation IPv4 — dernier octet masqué
    Given gdpr.anonymize_ip = true (défaut)
    When un visiteur avec IP "192.168.1.42" est loggué
    Then dans les logs, l'IP apparaît comme "192.168.1.0"
    And le VisitorState reste indexé par l'ip_hash de l'IP réelle

  Scenario: Anonymisation IPv6 — 80 derniers bits masqués
    Given gdpr.anonymize_ip = true
    When un visiteur avec IP "2001:db8:85a3::8a2e:370:7334" est loggué
    Then dans les logs, l'IP apparaît tronquée aux 48 premiers bits

  Scenario: Sans anonymisation — IP en clair dans les journaux, hashée dans les métriques
    Given gdpr.anonymize_ip = false
    When un visiteur envoie une requête
    Then l'IP en clair figure dans les security events
    And dans les métriques Prometheus, aucune IP ni ip_hash n'est exposée

  Scenario: Anonymisation n'empêche pas la protection IP-based
    Given gdpr.anonymize_ip = true
    And l'IP "198.51.100.42" est en blacklist
    When ce visiteur envoie une requête
    Then l'IP est quand même reconnue dans la blacklist (avant anonymisation)
    And la requête reçoit HTTP 403

  # ── Droit à l'effacement ────────────────────────────────────────────────────

  Scenario: Droit à l'effacement — suppression de toutes les données d'un visiteur
    Given le hash ip_hash "a3f4b2c1d0e5" est connu du WAF
    When DELETE /waf/admin/visitors/a3f4b2c1d0e5 est appelé (admin authentifié)
    Then le VisitorState est supprimé
    And le profil comportemental est supprimé
    And les rate buckets sont supprimés
    And l'action est journalisée dans l'audit trail avec action="reset_visitor"
    And HTTP 204 est retourné
    # POST /waf/admin/gdpr/erase {"ip": …} efface le même état et journalise
    # action="gdpr_erase" (audit-entry.schema.json, actions en minuscules).

  Scenario: Effacement ne supprime pas les security events passés
    Given des security events avec ip_hash "a3f4b2c1d0e5" existent en mémoire
    When DELETE /waf/admin/visitors/a3f4b2c1d0e5 est appelé
    Then les security events NE sont PAS supprimés
    Note: La conservation est légitime pour la finalité sécurité (période limitée par la rétention)

  # ── Logs et query parameters ────────────────────────────────────────────────

  Scenario: Query parameters non loggués en clair au niveau INFO
    Given un visiteur visite "/search?q=mon+email&token=secret123"
    When le WAF logue la requête au niveau INFO
    Then le champ "path" dans le log contient "/search" (sans query string)
    And les paramètres "q" et "token" ne sont pas loggués

  Scenario: Query parameters loggués au niveau DEBUG uniquement
    Given logging.level = "debug"
    When le WAF logue la requête
    Then les query parameters peuvent être loggués (admin a explicitement activé DEBUG)
    Note: Le mode DEBUG ne doit jamais être utilisé en production

  # ── Rapport de conformité ───────────────────────────────────────────────────

  @deferred
  Scenario: Rapport RGPD disponible via API admin
    When GET /waf/admin/privacy/report
    Then la réponse JSON contient:
      | data_categories    | liste des catégories de données traitées    |
      | retention_policy   | durées de conservation configurées          |
      | anonymization      | mode d'anonymisation actif                  |
      | third_party_sharing| si AbuseIPDB est activé (transfert tiers)   |
      | legal_basis        | base légale (intérêt légitime)              |
