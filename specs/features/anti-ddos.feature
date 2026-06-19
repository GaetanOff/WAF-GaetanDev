Feature: Protection Anti-DDoS
  En tant que WAF,
  Je veux détecter et atténuer les attaques DDoS
  Afin de protéger le serveur d'origine de la surcharge.

  Background:
    Given le WAF est configuré avec rate_limit.requests_per_second = 50
    And le WAF est configuré avec rate_limit.burst = 100
    And le WAF est configuré avec antiddos.global_requests_per_second = 50000
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

  Scenario: Pression globale élevée — pas de blocage global automatique
    Given le WAF observe un trafic global supérieur au seuil configuré
    When un nouveau visiteur sans score de confiance envoie une requête
    Then le WAF ne retourne pas HTTP 503 uniquement à cause de la pression globale
    And la requête reçoit une mitigation réversible "CHALLENGE" ou "THROTTLE"
    And le log indique global_pressure="elevated"

  Scenario: Pression globale critique — visiteurs connus favorisés
    Given le WAF observe un trafic global critique
    And un visiteur possède un cookie WAF valide
    When ce visiteur envoie une requête sous sa limite par IP
    Then la requête est transmise à l'upstream
    And le score du visiteur n'est pas diminué uniquement par la pression globale

  Scenario: Pression globale critique — abus par IP toujours limité
    Given le WAF observe un trafic global critique
    And un visiteur inconnu dépasse son rate limit par IP
    When il envoie une nouvelle requête
    Then la requête reçoit une réponse HTTP 429
    And le header "Retry-After" est présent dans la réponse 429
    And le log indique action="RATE_LIMIT"

  Scenario: Journalisation d'un événement de rate limiting
    Given un visiteur avec l'IP "5.5.5.5" déclenche le rate limit
    Then un événement de sécurité est journalisé
    And l'événement contient les champs: timestamp, request_id, ip, action="RATE_LIMIT", trust_score
    And l'événement ne contient pas de query string sensible

  # --- Mode "sous attaque" (FR-39, ADR-018) ---

  Scenario: Sous attaque — flood L7 distribué forcé au challenge
    Given antiddos.under_attack.enabled = true et scope = "per_domain"
    And antiddos.under_attack.trigger_pressure = "high"
    And la pression du domaine "status.gaetandev.fr" atteint "high"
    When un visiteur sans cookie WAF valide envoie un "GET /" sur ce domaine
    Then la requête reçoit un challenge JS "CHALLENGE"
    And le challenge est forcé même si le risk_score est sous le palier challenge
    And le log indique under_attack=true

  Scenario: Sous attaque — visiteur avec clearance passe sans friction
    Given le domaine "status.gaetandev.fr" est en mode sous attaque
    And un visiteur possède un cookie WAF "waf_session" valide
    When ce visiteur envoie une requête sous sa limite par IP
    Then la requête est transmise à l'upstream
    And aucun challenge n'est servi

  Scenario: Sous attaque — récupération humaine via PoW
    Given le domaine "status.gaetandev.fr" est en mode sous attaque
    And un humain sans cookie reçoit un challenge JS
    When il résout la preuve de travail et obtient un cookie "waf_session"
    Then ses requêtes suivantes sont transmises à l'upstream sans challenge

  Scenario: Sous attaque — bot vérifié non challengé
    Given le domaine "status.gaetandev.fr" est en mode sous attaque
    And un visiteur est un "Googlebot" vérifié par reverse-DNS forward-confirm
    When il envoie une requête
    Then la requête n'est pas challengée
    And la requête est transmise à l'upstream

  Scenario: Sous attaque — client API non-navigateur non challengé
    Given le domaine "api.gaetandev.fr" est en mode sous attaque
    When un client sans cookie envoie une requête avec l'en-tête "Accept: application/json"
    Then la requête ne reçoit pas de page de challenge JS
    And la requête reste soumise au rate limiting par IP et au moteur de risque

  Scenario: Sous attaque — portée par domaine
    Given antiddos.under_attack.scope = "per_domain"
    And le domaine "status.gaetandev.fr" est en mode sous attaque
    And le domaine "nextcloud.gaetandev.fr" reçoit un trafic normal
    When un visiteur sans cookie envoie un "GET /" sur "nextcloud.gaetandev.fr"
    Then la requête n'est pas forcée au challenge par le mode sous attaque

  Scenario: Sous attaque — hystérésis de sortie
    Given le domaine "status.gaetandev.fr" est en mode sous attaque
    And antiddos.under_attack.exit_pressure = "elevated" et cooldown = "30s"
    When la pression retombe à "elevated" pendant moins de 30 secondes
    Then le domaine reste en mode sous attaque
    When la pression reste sous "elevated" pendant plus de 30 secondes
    Then le domaine quitte le mode sous attaque

  Scenario: Sous attaque — mode shadow calcule sans appliquer
    Given antiddos.under_attack.shadow = true
    And le domaine "status.gaetandev.fr" atteint la pression "high"
    When un visiteur sans cookie envoie un "GET /" sur ce domaine
    Then la requête n'est pas forcée au challenge
    And le log indique under_attack=true

  Scenario: Sous attaque — alerte d'entrée et de sortie
    Given alerting.enabled = true
    When le domaine "status.gaetandev.fr" entre en mode sous attaque
    Then une alerte est émise avec le trigger "under_attack" et le domaine concerné
    When le domaine quitte le mode sous attaque
    Then une alerte de fin est émise
