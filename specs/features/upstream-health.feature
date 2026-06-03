Feature: Upstream Health Checks & Load Balancing
  En tant que WAF,
  Je veux surveiller la santé des upstreams et distribuer le trafic intelligemment
  Afin de garantir la disponibilité du service même en cas de défaillance d'un serveur.

  Background:
    Given le WAF est configuré avec un pool de 2 upstreams:
      - upstream-A: "http://10.0.0.1:80" (primary, weight=1)
      - upstream-B: "http://10.0.0.2:80" (primary, weight=1)
      - upstream-C: "http://10.0.0.3:80" (backup)
    And health_check.enabled = true
    And health_check.interval = "10s"
    And health_check.failure_threshold = 3

  # ── Health Checks ─────────────────────────────────────────────────────────

  Scenario: Upstream sain — health check réussit
    Given upstream-A répond HEAD / avec HTTP 200
    When le health check s'exécute
    Then upstream-A est marqué UP
    And les requêtes continuent à lui être routées

  Scenario: Upstream indisponible après 3 échecs consécutifs
    Given upstream-A commence à retourner des erreurs 500 sur le health check
    When 3 health checks consécutifs échouent
    Then upstream-A est marqué DOWN
    And les requêtes sont routées uniquement vers upstream-B
    And un webhook "upstream_down" est envoyé
    And la métrique waf_upstream_health{upstream="upstream-A", status="down"} est mise à jour

  Scenario: Upstream qui revient après être tombé
    Given upstream-A était DOWN
    When 1 health check réussit (success_threshold = 1 par défaut)
    Then upstream-A est remis UP
    And les requêtes lui sont à nouveau routées
    And un webhook "upstream_recovered" est envoyé

  Scenario: Health check timeout
    Given upstream-A ne répond pas dans le délai health_check.timeout = 3s
    Then ce health check compte comme un échec
    And après failure_threshold échecs → upstream-A passé DOWN

  Scenario: Activation du backup quand tous les primaires sont DOWN
    Given upstream-A et upstream-B sont tous les deux DOWN
    When une requête arrive
    Then la requête est routée vers upstream-C (backup)
    And un webhook "upstream_down" (severity: critical) est envoyé

  Scenario: Tous les upstreams DOWN — page de maintenance
    Given upstream-A, upstream-B et upstream-C sont tous DOWN
    When une requête arrive
    Then le WAF retourne HTTP 503 avec la page de maintenance configurée
    And aucune requête n'est envoyée à aucun upstream

  Scenario: État des upstreams visible via l'API admin
    When GET /waf/admin/upstreams
    Then la réponse liste tous les upstreams avec leur statut:
      | address         | status | last_check | consecutive_failures | avg_latency_ms |
      | 10.0.0.1:80     | up     | <timestamp>| 0                    | 2.3            |
      | 10.0.0.2:80     | down   | <timestamp>| 3                    | null           |
      | 10.0.0.3:80     | standby| <timestamp>| 0                    | 1.8            |

  # ── Load Balancing ──────────────────────────────────────────────────────────

  Scenario: Round Robin — distribution équitable
    Given strategy = "round_robin"
    And upstream-A et upstream-B sont tous les deux UP (weight=1)
    When 100 requêtes arrivent
    Then environ 50 requêtes vont vers upstream-A
    And environ 50 requêtes vont vers upstream-B (±5% de tolérance)

  Scenario: Round Robin pondéré — distribution par poids
    Given upstream-A a weight=3, upstream-B a weight=1
    When 100 requêtes arrivent
    Then environ 75 requêtes vont vers upstream-A (weight 3/4)
    And environ 25 requêtes vont vers upstream-B (weight 1/4)

  Scenario: IP Hash — même IP toujours vers même upstream
    Given strategy = "ip_hash"
    When l'IP "1.2.3.4" envoie 10 requêtes
    Then toutes les 10 requêtes vont vers le même upstream
    When l'IP "5.6.7.8" envoie 10 requêtes
    Then toutes vont vers le même upstream (potentiellement différent de 1.2.3.4)

  Scenario: IP Hash — redistribution si upstream tombe
    Given strategy = "ip_hash" et l'IP "1.2.3.4" est assignée à upstream-A
    When upstream-A tombe (DOWN)
    Then les prochaines requêtes de "1.2.3.4" sont routées vers upstream-B
    And quand upstream-A revient, "1.2.3.4" est réassignée à upstream-A

  Scenario: Least Connections — upstream le moins chargé
    Given strategy = "least_conn"
    And upstream-A a 10 connexions actives, upstream-B a 2 connexions actives
    When une nouvelle requête arrive
    Then la requête va vers upstream-B (moins de connexions)

  # ── Retry ──────────────────────────────────────────────────────────────────

  Scenario: Retry sur upstream différent après erreur réseau
    Given retry.enabled = true et retry.max_retries = 1
    And upstream-A répond avec une erreur réseau (connexion refusée)
    When une requête GET arrive et upstream-A est sélectionné
    Then le WAF essaie sur upstream-B automatiquement
    And si upstream-B répond 200, le client reçoit 200
    And la métrique waf_upstream_retries_total est incrémentée

  Scenario: Pas de retry sur POST (non idempotent)
    Given une requête POST sur upstream-A échoue avec une erreur réseau
    When le WAF traite l'erreur
    Then aucun retry n'est effectué
    And le client reçoit HTTP 502

  Scenario: Health check non impacté par le graceful shutdown
    Given le WAF reçoit SIGTERM et commence le graceful shutdown
    When les health checks continuent de tourner pendant le shutdown
    Then les requêtes en cours sont terminées normalement
    And aucun nouveau health check n'est lancé après SIGTERM
