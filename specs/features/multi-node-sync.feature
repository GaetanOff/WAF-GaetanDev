Feature: Synchronisation Multi-Nœuds (Cluster Mode)
  En tant qu'administrateur d'un cluster WAF,
  Je veux que les décisions de sécurité soient partagées entre toutes les instances
  Afin qu'un bot bloqué sur un nœud soit bloqué sur tous les nœuds immédiatement.

  # Contrat : FR-20 (requirements-advanced.md), cluster-event.schema.json, bloc
  # cluster de config.schema.json. Tous les événements passent par un seul canal
  # Redis Pub/Sub, cluster.channel (défaut "waf:events"), le type étant porté par
  # l'événement. Les scénarios @deferred sont spécifiés mais NON implémentés
  # (audit du 2026-09-30) : ils ne sont pas un critère d'acceptation.

  Background:
    Given le WAF est configuré avec cluster.enabled = true
    And les 3 instances partagent le même challenge.secret_key (clé de signature des événements)
    And storage.redis pointe vers "redis:6379" (la connexion du bus Pub/Sub)
    And 3 instances WAF sont actives: WAF-1, WAF-2, WAF-3

  Scenario: Ajout d'une IP en blacklist — propagation immédiate
    Given un administrateur ajoute "5.5.5.5" en blacklist via l'API de WAF-1
    When WAF-1 publie l'événement "blacklist_add" sur cluster.channel
    Then WAF-2 et WAF-3 reçoivent l'événement en < 100ms
    And les trois instances bloquent "5.5.5.5" simultanemément

  Scenario: Retrait d'une IP de la blacklist — propagation
    Given "5.5.5.5" a été ajouté en blacklist via l'API de WAF-1 et propagé
    When un administrateur retire "5.5.5.5" via l'API de WAF-1
    Then WAF-1 publie l'événement "blacklist_remove"
    And WAF-2 et WAF-3 ne bloquent plus "5.5.5.5"

  Scenario: Événement rejoué hors fenêtre — ignoré
    Given un message "blacklist_add" valide, signé, capturé sur le canal il y a 10 minutes
    When il est republié sur cluster.channel
    Then aucun nœud ne l'applique
    And waf_cluster_rejected_events_total est incrémenté

  Scenario: Circuit-breaker ouvert — propagation aux autres nœuds
    Given WAF-1 ouvre le circuit-breaker pour l'IP "6.6.6.6" (5 violations)
    When WAF-1 publie l'événement "circuit_open" sur cluster.channel
    Then WAF-2 et WAF-3 bloquent également l'IP "6.6.6.6" immédiatement
    And la durée du blocage est la même sur tous les nœuds

  Scenario: Un nœud ignore l'écho de ses propres événements
    Given WAF-1 publie un événement "blacklist_add"
    When Redis Pub/Sub le lui renvoie
    Then WAF-1 ne l'applique pas une seconde fois (l'événement porte l'identifiant du nœud émetteur)

  Scenario: Événement non signé ou mal signé — ignoré
    Given un client Redis publie sur cluster.channel un "blacklist_add" de "0.0.0.0/0" sans signature valide
    When WAF-2 reçoit le message
    Then WAF-2 ne l'applique pas
    And waf_cluster_rejected_events_total est incrémenté sur WAF-2

  Scenario: Événement de type inconnu — ignoré
    Given WAF-1 publie un événement correctement signé de type "reboot"
    When WAF-2 le reçoit
    Then WAF-2 ne l'applique pas
    And waf_cluster_sync_events_total ne crée aucune série pour ce type
    And waf_cluster_rejected_events_total est incrémenté sur WAF-2

  Scenario: Mode cluster sans secret partagé — refusé au démarrage
    Given cluster.enabled = true
    And challenge.secret_key est vide
    When le WAF charge sa configuration
    Then le démarrage échoue : les événements ne peuvent pas être signés

  Scenario: Publication non bloquante
    Given Redis est lent ou indisponible
    When WAF-1 ouvre un circuit-breaker sur le chemin de requête
    Then la requête n'attend pas Redis (événement mis en file, abandonné si la file est pleine)

  Scenario: Score très bas partagé — visiteur dangereux
    Given WAF-1 détecte un visiteur dont le score passe sous 5 (très dangereux, ici 3)
    When WAF-1 publie l'événement "score_critical" sur cluster.channel
    Then WAF-2 et WAF-3 mettent à jour le score de ce visiteur dans leur store local

  @deferred
  Scenario: Mode dégradé global — coordination
    Given WAF-1 passe en mode dégradé (trafic > 200% baseline)
    When WAF-1 publie l'événement "degraded_mode" sur cluster.channel
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
    Given WAF-2 a appliqué un événement "blacklist_add" reçu de WAF-1
    When GET /waf/metrics sur WAF-2
    Then waf_cluster_sync_events_total{type="blacklist_add"} vaut 1

  @deferred
  Scenario: Métriques de synchronisation détaillées
    When GET /waf/metrics sur WAF-1
    Then les métriques contiennent:
      | waf_cluster_sync_events_published_total | événements publiés  |
      | waf_cluster_sync_lag_seconds            | latence de sync     |
      | waf_cluster_redis_connected             | 1 si connecté       |

  Scenario: Nœud qui rejoint le cluster — pas d'état initial partagé
    Given WAF-4 est une nouvelle instance qui rejoint le cluster
    When WAF-4 démarre
    Then WAF-4 commence avec un état local vide
    And il recevra les nouveaux événements Pub/Sub à partir de maintenant
    And il ne récupère pas l'historique des états (eventual consistency, pas de snapshot)

  Scenario: Rate limiting distribué (mode optionnel)
    Given storage.backend = "redis" sur les trois instances (buckets partagés, ADR-021)
    When la même IP "7.7.7.7" envoie 40 req/s sur WAF-1 ET 40 req/s sur WAF-2
    Then le rate limit global de 50 req/s est respecté (via Redis counters)
    And les deux instances coordonnent le rate limit
