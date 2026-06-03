Feature: Protection Anti-DDoS
  En tant que WAF,
  Je veux détecter et atténuer les attaques DDoS
  Afin de protéger le serveur d'origine de la surcharge.

  Background:
    Given le WAF est configuré avec rate_limit.requests_per_second = 50
    And le WAF est configuré avec rate_limit.burst = 100
    And le WAF est configuré avec trust.block_threshold = 10

  Scenario: Rate limiting — requêtes normales passent
    Given un visiteur avec l'IP "1.2.3.4"
    When il envoie 40 requêtes en 1 seconde
    Then toutes les requêtes sont transmises à l'upstream
    And le score du visiteur n'est pas diminué par le rate limit

  Scenario: Rate limiting — dépassement du burst
    Given un visiteur avec l'IP "1.2.3.4"
    When il envoie 150 requêtes en 1 seconde
    Then les 100 premières requêtes sont transmises (burst)
    And les requêtes suivantes reçoivent une réponse HTTP 429
    And le header "Retry-After" est présent dans la réponse 429
    And le score du visiteur est décrémenté de 10

  Scenario: Rate limiting — récupération après 429
    Given un visiteur avec l'IP "1.2.3.4" qui a reçu un 429
    When 2 secondes s'écoulent
    And il envoie 1 nouvelle requête
    Then la requête est transmise à l'upstream
    And la réponse n'est pas 429

  Scenario: Circuit-breaker — blocage temporaire après violations répétées
    Given un visiteur avec l'IP "1.2.3.4"
    And le visiteur a atteint le rate limit 5 fois consécutives
    When il envoie une nouvelle requête
    Then la requête reçoit une réponse HTTP 403
    And le log indique action="CIRCUIT_BREAK"
    And le circuit-breaker expire après 300 secondes

  Scenario: Protection IP whitelistée — pas de rate limiting
    Given l'IP "10.0.0.1" est dans la whitelist
    When cette IP envoie 1000 requêtes en 1 seconde
    Then toutes les requêtes sont transmises à l'upstream
    And aucun 429 n'est retourné

  Scenario: Seuil global de trafic dépassé
    Given le WAF est en mode de protection renforcée (trafic global > seuil)
    When un nouveau visiteur sans score de confiance envoie une requête
    Then le WAF retourne HTTP 503 avec header "Retry-After: 5"
    And le log indique reason="global_rate_exceeded"

  Scenario: Journalisation d'un événement de rate limiting
    Given un visiteur avec l'IP "5.5.5.5" déclenche le rate limit
    Then un événement de sécurité est journalisé
    And l'événement contient les champs: timestamp, request_id, ip, action="RATE_LIMIT", trust_score
    And l'événement ne contient pas de query string sensible
