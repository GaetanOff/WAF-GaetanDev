Feature: Rate Limiting par IP (FR-03)
  En tant qu'opérateur du WAF,
  Je veux limiter le débit de chaque IP sur trois fenêtres (seconde, minute, heure)
  Afin qu'un client ne puisse ni saturer l'origine en rafale, ni la marteler lentement pendant des heures.

  Background:
    Given le WAF est configuré avec rate_limit.enabled = true
    And rate_limit.requests_per_second = 50
    And rate_limit.burst = 100
    And rate_limit.requests_per_minute = 1000
    And rate_limit.requests_per_hour = 10000

  Scenario: Trafic nominal — les trois fenêtres ont un jeton
    Given une IP "203.0.113.10" n'a envoyé aucune requête
    When elle envoie 10 requêtes en 1 seconde
    Then les 10 requêtes sont transmises à l'upstream
    And aucun en-tête "Retry-After" n'est renvoyé

  Scenario: Fenêtre seconde dépassée — burst épuisé
    Given une IP "203.0.113.11" épuise les 100 jetons de burst
    When elle envoie une requête supplémentaire dans la même seconde
    Then le WAF répond HTTP 429
    And l'en-tête "Retry-After" est présent et >= 1
    And le log porte reason = "rate_limit_exceeded"
    And le score de confiance du visiteur est pénalisé de -10

  Scenario: Fenêtre minute dépassée — la rafale passe, le débit soutenu non
    Given une IP "203.0.113.12" a consommé 1000 requêtes dans la minute courante
    When elle envoie une requête supplémentaire, en restant sous 50 req/s
    Then le WAF répond HTTP 429
    And le log porte reason = "rate_limit_exceeded_minute"
    And le "Retry-After" annoncé correspond au délai de recharge de la fenêtre minute

  Scenario: Fenêtre heure dépassée — martèlement lent
    Given une IP "203.0.113.13" a consommé 10000 requêtes dans l'heure courante
    When elle envoie une requête supplémentaire, en restant sous 1000 req/min
    Then le WAF répond HTTP 429
    And le log porte reason = "rate_limit_exceeded_hour"

  Scenario: Un refus par une fenêtre ne consomme pas les jetons des autres
    Given une IP "203.0.113.14" a épuisé sa fenêtre minute
    And sa fenêtre seconde dispose de 100 jetons
    When elle envoie 5 requêtes refusées par la fenêtre minute
    Then sa fenêtre seconde dispose toujours de 100 jetons
    And dès que la fenêtre minute se recharge, ses 100 jetons de burst sont intacts

  Scenario: Retry-After = le plus grand délai des fenêtres qui refusent
    Given une IP "203.0.113.15" a épuisé sa fenêtre seconde et sa fenêtre heure
    When elle envoie une requête
    Then le WAF répond HTTP 429
    And le "Retry-After" renvoyé est celui de la fenêtre heure (le plus long)

  Scenario: Fenêtre désactivée par la configuration
    Given rate_limit.requests_per_minute = 0
    And rate_limit.requests_per_hour = 0
    When une IP envoie 5000 requêtes réparties sur 2 minutes, sous 50 req/s
    Then aucune requête n'est refusée pour dépassement de fenêtre minute ou heure
    And seule la fenêtre seconde continue de s'appliquer

  Scenario: IP en whitelist — exemptée des trois fenêtres
    Given l'IP "10.0.0.5" est en whitelist
    When elle envoie 10000 requêtes en 1 minute
    Then aucune requête n'est refusée par le rate limiting
    And aucun jeton n'est consommé pour cette IP

  Scenario: Pression globale — resserrement des trois fenêtres, sans pénalité
    Given la pression globale anti-DDoS est "high" (facteur 0.5)
    And un visiteur non TRUSTED "203.0.113.16"
    When son débit dépasse la moitié du débit nominal d'une des trois fenêtres
    Then le WAF répond HTTP 429 avec reason = "rate_limit_pressure"
    And le score de confiance du visiteur n'est PAS pénalisé
    And aucune violation de circuit-breaker n'est enregistrée

  Scenario: Configuration incohérente rejetée au démarrage
    Given rate_limit.requests_per_minute = 5000
    And rate_limit.requests_per_hour = 1000
    When le WAF démarre
    Then le démarrage échoue avec une erreur de validation
    And l'erreur nomme "rate_limit.requests_per_hour"
