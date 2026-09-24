Feature: Upstream Health Checks & Load Balancing
  En tant que WAF,
  Je veux surveiller la santé des upstreams et distribuer le trafic intelligemment
  Afin de garantir la disponibilité du service même en cas de défaillance d'un serveur.

  # Contrat : specs/schemas/upstream-pool.schema.json v2.0.0 (= bloc
  # upstream_pool de config.schema.json). Les scénarios @deferred sont
  # spécifiés mais NON implémentés (audit du 2026-09-24, point 2.3) : ils ne
  # sont pas un critère d'acceptation.

  Background:
    Given le WAF est configuré avec upstream_pool.enabled = true et 3 membres:
      - upstream-A: "http://10.0.0.1:80" (principal, weight=1)
      - upstream-B: "http://10.0.0.2:80" (principal, weight=1)
      - upstream-C: "http://10.0.0.3:80" (backup)
    And health_check.interval = "10s"
    And health_check.healthy_threshold = 2
    And health_check.unhealthy_threshold = 3

  # ── Health Checks ─────────────────────────────────────────────────────────

  Scenario: Upstream sain — health check réussit
    Given upstream-A répond GET /healthz avec HTTP 200
    When le health check s'exécute
    Then upstream-A reste en service
    And les requêtes continuent à lui être routées

  Scenario: Upstream retiré après 3 échecs consécutifs
    Given upstream-A commence à retourner des erreurs 500 sur le health check
    When 3 health checks consécutifs échouent (unhealthy_threshold)
    Then upstream-A est retiré du service
    And les requêtes sont routées uniquement vers upstream-B

  Scenario: Erreur de proxy — retrait immédiat
    Given upstream-A refuse une connexion pendant le proxying d'une requête
    Then le client reçoit HTTP 502
    And upstream-A est retiré du service sans attendre unhealthy_threshold
    And les sondes le remettront en service après healthy_threshold succès

  Scenario: Upstream qui revient après être tombé
    Given upstream-A était hors service
    When 2 health checks consécutifs réussissent (healthy_threshold)
    Then upstream-A est remis en service
    And les requêtes lui sont à nouveau routées

  Scenario: Health check timeout
    Given upstream-A ne répond pas dans le délai health_check.timeout = 2s
    Then ce health check compte comme un échec

  Scenario: Activation du backup quand tous les principaux sont hors service
    Given upstream-A et upstream-B sont tous les deux hors service
    When une requête arrive
    Then la requête est routée vers upstream-C (backup)

  Scenario: Tous les upstreams hors service
    Given upstream-A, upstream-B et upstream-C sont tous hors service
    When une requête arrive
    Then le WAF retourne HTTP 502 « no healthy upstream »
    And aucune requête n'est envoyée à aucun upstream

  Scenario: Pool activé sans réglage de sonde — défauts documentés
    Given upstream_pool.enabled = true avec seulement la liste des upstreams
    When le WAF démarre
    Then la sonde utilise /healthz toutes les 10s, timeout 2s, seuils 2 et 3

  # ── Load Balancing ──────────────────────────────────────────────────────────

  Scenario: Round Robin — distribution équitable
    Given strategy = "round_robin"
    And upstream-A et upstream-B sont tous les deux en service
    When 100 requêtes arrivent
    Then 50 requêtes vont vers upstream-A et 50 vers upstream-B

  Scenario: Weighted — distribution par poids
    Given strategy = "weighted"
    And upstream-A a weight=3, upstream-B a weight=1
    When 100 requêtes arrivent
    Then environ 75 requêtes vont vers upstream-A et 25 vers upstream-B
    # weight n'est lu que par strategy: weighted ; round_robin l'ignore.

  Scenario: IP Hash — même IP toujours vers même upstream
    Given strategy = "ip_hash"
    When l'IP "1.2.3.4" envoie 10 requêtes
    Then toutes les 10 requêtes vont vers le même upstream

  Scenario: IP Hash — redistribution si upstream tombe
    Given strategy = "ip_hash" et l'IP "1.2.3.4" est assignée à upstream-A
    When upstream-A est retiré du service
    Then les prochaines requêtes de "1.2.3.4" sont routées vers un autre membre sain

  Scenario: Least Connections — upstream le moins chargé
    Given strategy = "least_conn"
    And upstream-A a 10 requêtes en cours, upstream-B en a 2
    When une nouvelle requête arrive
    Then la requête va vers upstream-B

  Scenario: Arrêt — les sondes s'arrêtent avec le WAF
    Given le WAF reçoit SIGTERM
    Then les requêtes en cours sont terminées normalement
    And aucun nouveau health check n'est lancé après l'arrêt

  # ── Différés : spécifiés, non implémentés ───────────────────────────────────

  @deferred
  Scenario: Retry sur un autre membre après erreur réseau (méthodes idempotentes)
    Given retry.enabled = true et retry.max_retries = 1
    And upstream-A répond avec une erreur réseau à une requête GET
    Then le WAF réessaie sur upstream-B et le client reçoit sa réponse
    And waf_upstream_retries_total est incrémenté
    # Aujourd'hui : 502 immédiat, upstream-A retiré du service (failover pour
    # les requêtes suivantes seulement). Aucune clé retry n'est acceptée.

  @deferred
  Scenario: Pas de retry sur POST (non idempotent)
    Given une requête POST sur upstream-A échoue avec une erreur réseau
    Then aucun retry n'est effectué et le client reçoit HTTP 502

  @deferred
  Scenario: Tous les upstreams hors service — page de maintenance 503
    Given tous les membres sont hors service
    When une requête arrive
    Then le WAF retourne HTTP 503 avec la page de maintenance (FR-32)

  @deferred
  Scenario: Alertes et métriques de santé des upstreams
    When upstream-A est retiré puis remis en service
    Then les webhooks upstream_down puis upstream_recovered sont envoyés
    And waf_upstream_health{upstream} reflète chaque transition

  @deferred
  Scenario: État des upstreams visible via l'API admin
    When GET /waf/admin/upstreams
    Then la réponse liste chaque membre avec address, status, last_check, consecutive_failures, avg_latency_ms

  @deferred
  Scenario: Sonde configurable — méthode, statut et corps attendus
    Given health_check.method = "HEAD", expected_status = 204, expected_body = "ok"
    When le health check s'exécute
    Then seul un 204 dont le corps contient "ok" est un succès
