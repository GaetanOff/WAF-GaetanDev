Feature: Backend de stockage de l'état visiteurs (ADR-002, ADR-021)
  En tant qu'opérateur d'un déploiement multi-instances,
  Je veux que l'état des visiteurs soit partagé via Redis
  Afin qu'un visiteur ne reparte pas de zéro à chaque nœud, sans qu'une panne Redis n'arrête le WAF.

  Scenario: Backend memory (défaut) — aucun état partagé
    Given storage.backend = "memory"
    When le WAF démarre
    Then l'état visiteurs est tenu en mémoire, borné par trust.max_visitors
    And aucune connexion Redis n'est ouverte pour le stockage

  Scenario: Backend redis — état partagé entre instances
    Given storage.backend = "redis"
    And storage.redis.address = "redis:6379"
    And deux instances WAF-1 et WAF-2 partagent cette instance Redis
    When WAF-1 abaisse le score d'un visiteur à 20
    Then WAF-2 lit le score 20 pour ce visiteur
    And la clé Redis porte le préfixe "waf:visitor:"
    And elle expire à l'échéance portée par l'état (trust.score_ttl)

  Scenario: Redis injoignable au démarrage — échec explicite
    Given storage.backend = "redis"
    And storage.redis.address pointe vers une instance inexistante
    When le WAF démarre
    Then le démarrage échoue avec une erreur nommant Redis
    And le WAF ne démarre PAS silencieusement sur un stockage mémoire

  Scenario: Perte de Redis en cours d'exploitation — mode dégradé autonome
    Given storage.backend = "redis" et le WAF sert du trafic
    When Redis devient injoignable
    Then après 3 erreurs consécutives le nœud sert son état local
    And la métrique "waf_storage_degraded" passe à 1
    And "waf_storage_errors_total" est incrémentée
    And les requêtes continuent d'être traitées (FR-20)

  Scenario: Retour de Redis — sortie du mode dégradé
    Given le nœud est en mode dégradé
    When Redis redevient joignable
    Then le nœud reprend ses lectures sur Redis à la fin de la fenêtre dégradée
    And la métrique "waf_storage_degraded" repasse à 0

  Scenario: Écriture traversante — l'état local reste chaud
    Given storage.backend = "redis" en mode nominal
    When le WAF écrit l'état d'un visiteur
    Then l'écriture est faite dans Redis et dans le store local
    And un basculement en mode dégradé retrouve cet état sans repartir de zéro

  Scenario: Liste des visiteurs pour l'API admin — SCAN borné
    Given storage.backend = "redis" et 500 000 visiteurs en base
    When un administrateur appelle GET /admin/visitors
    Then le WAF parcourt les clés par SCAN
    And il ne renvoie pas plus de trust.max_visitors entrées
    And aucune commande KEYS n'est émise

  Scenario: Backend redis sans bloc redis — rejeté au démarrage
    Given storage.backend = "redis"
    And aucun bloc storage.redis n'est défini
    When le WAF démarre
    Then le démarrage échoue avec une erreur de validation nommant "storage.redis"
