Feature: Synchronisation Multi-Nœuds (Cluster Mode)
  En tant qu'administrateur d'un cluster WAF,
  Je veux que les décisions de sécurité soient partagées entre toutes les instances
  Afin qu'un bot bloqué sur un nœud soit bloqué sur tous les nœuds immédiatement.

  Background:
    Given le WAF est configuré avec cluster.enabled = true
    And cluster.redis_address = "redis:6379"
    And 3 instances WAF sont actives: WAF-1, WAF-2, WAF-3

  Scenario: Ajout d'une IP en blacklist — propagation immédiate
    Given un administrateur ajoute "5.5.5.5" en blacklist via l'API de WAF-1
    When WAF-1 publie l'événement sur Redis Pub/Sub channel "waf:blacklist"
    Then WAF-2 et WAF-3 reçoivent l'événement en < 100ms
    And les trois instances bloquent "5.5.5.5" simultanemément

  Scenario: Circuit-breaker ouvert — propagation aux autres nœuds
    Given WAF-1 ouvre le circuit-breaker pour l'IP "6.6.6.6" (5 violations)
    When WAF-1 publie l'événement sur Redis Pub/Sub channel "waf:circuit_breaker"
    Then WAF-2 et WAF-3 bloquent également l'IP "6.6.6.6" immédiatement
    And la durée du blocage est la même sur tous les nœuds

  Scenario: Score très bas partagé — visiteur dangereux
    Given WAF-1 détecte un visiteur avec score = 3 (très dangereux)
    When WAF-1 publie le score sur "waf:threat_share"
    Then WAF-2 et WAF-3 mettent à jour le score de ce visiteur dans leur store local

  Scenario: Mode dégradé global — coordination
    Given WAF-1 passe en mode dégradé (trafic > 200% baseline)
    When WAF-1 publie l'événement sur "waf:degraded_mode"
    Then WAF-2 et WAF-3 passent également en mode dégradé dans les 200ms

  Scenario: Eventual consistency — pas de blocage sur perte réseau
    Given la connexion Redis est perdue momentanément
    When WAF-1 traite des requêtes pendant la perte de connexion
    Then WAF-1 continue à fonctionner avec son état local (mode autonome)
    And les décisions ne sont plus propagées pendant la coupure
    And quand Redis revient, la connexion est rétablie automatiquement

  Scenario: Résistance à la partition — nœud Redis down
    Given Redis est complètement indisponible
    When les 3 instances WAF continuent à recevoir du trafic
    Then chaque instance fonctionne indépendamment
    And les décisions de sécurité locales sont toujours appliquées
    And aucune instance ne crash

  Scenario: Métriques de synchronisation
    When GET /waf/metrics sur WAF-1
    Then les métriques contiennent:
      | waf_cluster_sync_events_published_total | événements publiés  |
      | waf_cluster_sync_events_received_total  | événements reçus    |
      | waf_cluster_sync_lag_seconds            | latence de sync     |
      | waf_cluster_redis_connected             | 1 si connecté       |

  Scenario: Nœud qui rejoint le cluster — pas d'état initial partagé
    Given WAF-4 est une nouvelle instance qui rejoint le cluster
    When WAF-4 démarre
    Then WAF-4 commence avec un état local vide
    And il recevra les nouveaux événements Pub/Sub à partir de maintenant
    And il ne récupère pas l'historique des états (eventual consistency, pas de snapshot)

  Scenario: Rate limiting distribué (mode optionnel)
    Given cluster.distributed_rate_limit = true (Redis comme backend de rate limit)
    When la même IP "7.7.7.7" envoie 40 req/s sur WAF-1 ET 40 req/s sur WAF-2
    Then le rate limit global de 50 req/s est respecté (via Redis counters)
    And les deux instances coordonnent le rate limit
