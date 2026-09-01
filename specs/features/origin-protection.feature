Feature: Protection de l'Origine
  En tant qu'administrateur du WAF,
  Je veux m'assurer que l'upstream ne reçoit des requêtes que via le WAF
  Afin d'empêcher les attaquants de contourner la protection en accédant directement à l'origine.

  Background:
    Given le WAF est configuré avec origin_protection.enabled = true
    And origin_protection.secret est défini (ou via WAF_ORIGIN_SECRET env var)

  Scenario: Requête proxifiée — header secret injecté
    Given un visiteur légitime envoie une requête
    When le WAF proxifie la requête vers l'upstream
    Then l'upstream reçoit le header "X-WAF-Origin-Token: <valeur_hmac>"
    And le header est un HMAC-SHA256(secret, domain + floor(timestamp/3600))

  Scenario: Token HMAC rotatif — change chaque heure
    Given la requête est traitée à 14h59
    Then le token est HMAC(secret, "example.com" + "14")
    Given la requête suivante est traitée à 15h01
    Then le token est HMAC(secret, "example.com" + "15") — différent

  Scenario: Fenêtre de tolérance — 2 heures pour éviter les coupures
    Given il est 15h01 et le token courant est pour l'heure 15
    When l'upstream vérifie le token reçu
    Then le token de l'heure 14 (ancienne heure) est aussi valide
    And le token de l'heure 16 (future) n'est pas valide

  Scenario: Endpoint de validation pour l'upstream
    Given le middleware upstream veut vérifier le token
    When il envoie GET /waf/origin/verify avec header X-WAF-Origin-Token
    Then le WAF retourne HTTP 200 {"valid": true} si le token est correct
    And HTTP 401 {"valid": false} si invalide

  Scenario: L'assainissement d'ingress ne casse pas l'endpoint de validation
    Given l'assainissement d'ingress supprime tout en-tête X-WAF-* fourni par le client (FR-30)
    When l'upstream envoie GET /waf/origin/verify avec un X-WAF-Origin-Token valide
    Then le WAF retourne HTTP 200 {"valid": true}
    # Le token est capturé avant l'assainissement et lu hors de r.Header : sans
    # cette exception, l'endpoint répondrait 401 à tout token, y compris valide.

  Scenario: Token forgé sur l'endpoint de validation — refusé
    Given un attaquant appelle lui-même l'endpoint de validation
    When il envoie GET /waf/origin/verify avec X-WAF-Origin-Token "forge"
    Then le WAF retourne HTTP 401 {"valid": false}
    # L'exception ne porte que sur la lisibilité de la valeur : elle reste
    # vérifiée par HMAC, donc infalsifiable sans le secret.

  Scenario: Token forgé sur une requête proxifiée — jamais transmis à l'upstream
    Given origin_protection.enabled = false (aucune injection côté WAF)
    When un client envoie une requête avec X-WAF-Origin-Token "forge"
    Then l'upstream ne reçoit pas cet en-tête
    # Un upstream qui ne vérifierait que la présence du header serait sinon
    # trompé par un en-tête forgé par le client — exactement l'attaque que FR-19
    # est censée fermer.

  Scenario: Upstream rejette les requêtes sans token (bypass direct)
    Given l'upstream est configuré avec le middleware de vérification WAF
    When un attaquant envoie une requête directement à l'upstream (sans passer par le WAF)
    Then l'upstream retourne HTTP 403 (header manquant ou invalide)
    And la protection est effective même si l'IP de l'origine est exposée

  Scenario: mTLS vers l'upstream
    Given origin_protection.mtls.enabled = true
    And origin_protection.mtls.cert et mtls.key sont configurés
    When le WAF proxifie une requête
    Then la connexion TLS vers l'upstream est établie avec le certificat client WAF
    And l'upstream peut vérifier que la requête vient bien du WAF via le certificat

  Scenario: Origin Protection désactivée — header non injecté
    Given origin_protection.enabled = false
    When le WAF proxifie une requête
    Then l'upstream ne reçoit pas le header X-WAF-Origin-Token
    And le comportement est identique à avant la feature

  Scenario: Rotation du secret — pas d'interruption
    Given l'administrateur change origin_protection.secret via hot-reload
    Then les nouvelles requêtes utilisent le nouveau secret
    And il y a une fenêtre de tolérance de 5 minutes (configurable) avec l'ancien secret
    And aucune requête légitime n'est rejetée pendant la transition
