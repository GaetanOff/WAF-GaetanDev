Feature: Système de score de confiance
  En tant que WAF,
  Je veux maintenir un score de confiance par visiteur
  Afin de prendre des décisions de filtrage contextuelles et adaptatives.

  Background:
    Given le WAF est configuré avec:
      | trust.initial_score        | 50  |
      | trust.challenge_threshold  | 40  |
      | trust.block_threshold      | 10  |
      | trust.score_ttl            | 1h  |

  Scenario: Nouveau visiteur — score initial
    Given une requête d'un nouveau visiteur IP "4.4.4.4"
    When le WAF crée l'entrée visiteur
    Then le score est initialisé à 50
    And l'état est "MONITORED" (entre 40 et 69)

  Scenario: Challenge réussi — score augmenté
    Given un visiteur avec score = 35
    When il réussit le challenge JavaScript
    Then le score devient 60 (35 + 25)
    And l'action passe de "CHALLENGE" à "PASS"

  Scenario: Navigation normale — score augmente progressivement
    Given un visiteur avec score = 60 et cookie valide
    When il effectue 10 requêtes légitimes espacées de 2 secondes
    Then le score augmente de +1 par requête (max +10/heure)
    And le score ne dépasse pas 100

  Scenario: Rate limit déclenché — score diminué
    Given un visiteur avec score = 55
    When il déclenche le rate limit
    Then le score devient 45 (55 - 10)
    And la requête reçoit HTTP 429

  Scenario: Honeypot touché — score à zéro
    Given un visiteur avec score = 80
    When il envoie une requête vers "/.env"
    Then le score devient 0
    And les requêtes suivantes reçoivent HTTP 403

  Scenario: Challenge échoué — score diminué
    Given un visiteur avec score = 45
    When il soumet un proof-of-work invalide
    Then le score devient 25 (45 - 20)
    And une nouvelle page de challenge est servie

  Scenario: Transitions d'état — TRUSTED → CHALLENGED
    Given un visiteur avec score = 75 (état TRUSTED)
    When il déclenche le rate limit 3 fois consécutives (3 × -10)
    Then le score devient 45 (75 - 30)
    And l'état reste "MONITORED"
    When il déclenche encore 1 violation (-10)
    Then le score devient 35
    And l'état devient "CHALLENGED"
    And la prochaine requête déclenche le challenge JS

  Scenario: Score expiré — reset au score initial
    Given un visiteur avec score = 90 qui n'a pas eu d'activité depuis 1h05
    When il envoie une nouvelle requête
    Then son score est réinitialisé à 50 (TTL expiré)
    And il reçoit le challenge JS si 50 > challenge_threshold est faux

  Scenario: Score maximum plafonné à 100
    Given un visiteur avec score = 98
    When il effectue 5 requêtes légitimes (+1 chacune)
    Then le score est plafonné à 100
    And aucun dépassement n'est possible

  Scenario: Blocage au seuil block_threshold
    Given un visiteur avec score = 12
    When il déclenche le rate limit (-10)
    Then le score devient 2
    And la requête reçoit HTTP 403
    And le log indique action="BLOCK" reason="score_below_block_threshold"
    And les requêtes suivantes sont bloquées jusqu'à expiration du TTL

  Scenario: Métriques exposées par score range
    When GET /waf/metrics est appelé
    Then les métriques contiennent:
      | waf_visitors_trusted_total    | nombre de visiteurs avec score 70-100  |
      | waf_visitors_monitored_total  | nombre de visiteurs avec score 40-69   |
      | waf_visitors_challenged_total | nombre de visiteurs avec score 11-39   |
      | waf_visitors_blocked_total    | nombre de visiteurs avec score 0-10    |
