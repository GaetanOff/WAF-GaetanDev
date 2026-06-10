Feature: Détection Anti-Bot
  En tant que WAF,
  Je veux identifier et bloquer les bots malveillants
  Afin de protéger le site des scrapers et automatisations non autorisées.

  Background:
    Given le WAF est opérationnel avec la configuration par défaut
    And le score initial pour tout nouveau visiteur est 50

  Scenario: Bot headless — User-Agent HeadlessChrome détecté
    Given une requête avec User-Agent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/120.0"
    When le WAF analyse la requête
    Then le score du visiteur est décrémenté de 30
    And l'action est "CHALLENGE"
    And le log indique reason="headless_browser_detected"

  Scenario: Bot connu — User-Agent Python-requests
    Given une requête avec User-Agent "python-requests/2.28.0"
    When le WAF analyse la requête
    Then le score du visiteur est décrémenté de 15
    And le visiteur est challengé si son score passe sous le seuil

  Scenario: User-Agent absent
    Given une requête HTTP sans header User-Agent
    When le WAF analyse la requête
    Then le score du visiteur est décrémenté de 20
    And l'action est "CHALLENGE"

  Scenario: Headers navigateur manquants (bot sans émulation)
    Given une requête avec User-Agent navigateur valide
    And la requête ne contient pas le header "Accept-Language"
    And la requête ne contient pas le header "Accept-Encoding"
    When le WAF analyse la requête
    Then le score est décrémenté de 10 (5 par header manquant)

  Scenario: Accès à un chemin honeypot
    Given un visiteur avec l'IP "2.3.4.5" et score = 60
    When il envoie une requête GET "/.env"
    Then le score du visiteur est mis à 0
    And la requête reçoit une réponse HTTP 403
    And un événement de sécurité est journalisé avec action="HONEYPOT"
    And le visiteur sera bloqué sur les requêtes suivantes

  Scenario: Accès à un chemin honeypot wp-admin
    Given un visiteur avec l'IP "9.8.7.6" et score = 80
    When il envoie une requête POST "/wp-admin"
    Then le score du visiteur est mis à 0
    And la requête reçoit une réponse HTTP 403

  Scenario: Mode calibration (shadow_mode) — blocage heuristique observé, non appliqué
    Given le WAF est configuré avec risk_engine.shadow_mode = true
    And un visiteur avec un User-Agent d'automation "Selenium"
    When il envoie une requête GET "/"
    Then le WAF n'applique PAS le blocage HTTP 403 (heuristique observée seulement)
    And le signal est publié au moteur de risque pour calibration

  Scenario: Mode calibration — le honeypot reste bloquant
    Given le WAF est configuré avec risk_engine.shadow_mode = true
    When un visiteur envoie une requête GET "/.env"
    Then la requête reçoit une réponse HTTP 403
    # Le honeypot est déterministe et sans faux positif : il bloque même en shadow.

  Scenario: Bot légitime — Googlebot whitelisté
    Given une requête avec User-Agent "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    When le WAF analyse la requête
    Then la requête est transmise à l'upstream sans challenge
    And aucun score n'est calculé pour ce visiteur

  Scenario: WebGL renderer headless détecté dans le fingerprint
    Given un visiteur soumet un challenge avec webgl_renderer = "Google SwiftShader"
    When le WAF valide le fingerprint
    Then le score est décrémenté de 30
    And la soumission du challenge est rejetée
    And le log indique reason="headless_webgl_renderer"

  Scenario: Signature Puppeteer/Selenium dans User-Agent
    Given une requête avec User-Agent contenant "Selenium"
    When le WAF analyse la requête
    Then le score est mis à 0
    And la requête est bloquée avec HTTP 403

  Scenario: Pattern de navigation anormal — trop rapide entre requêtes
    Given un visiteur qui a déjà passé le challenge (score = 75)
    When il envoie 200 requêtes en 2 secondes (100 req/s)
    Then le rate limit est déclenché
    And le score est décrémenté de 10
    And les requêtes excédentaires reçoivent 429
