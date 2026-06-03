Feature: Challenge JavaScript
  En tant que WAF,
  Je veux valider silencieusement les visiteurs via un challenge JavaScript
  Afin de distinguer les navigateurs humains des bots sans imposer de CAPTCHA.

  Background:
    Given le WAF est configuré avec challenge.pow_difficulty = 16
    And le WAF est configuré avec challenge.token_ttl = "30s"
    And le WAF est configuré avec challenge.min_elapsed_ms = 500
    And le WAF est configuré avec challenge.max_elapsed_ms = 10000

  Scenario: Nouveau visiteur sans cookie — page de challenge servie
    Given un nouveau visiteur avec l'IP "3.3.3.3" (score = 50, sous le seuil 40 non atteint)
    When il envoie une requête GET "/article/123"
    Then le WAF retourne HTTP 200 avec le contenu de la page challenge
    And la réponse contient un token de challenge signé embarqué dans le HTML
    And la réponse contient le CSS animé "Protected by GaetanDev.fr"
    And la réponse contient un chronomètre JavaScript
    And la réponse ne contient pas le contenu de la page "/article/123"

  Scenario: Visiteur sous le seuil de confiance — challenge déclenché
    Given un visiteur avec score = 30 (sous challenge_threshold = 40)
    When il envoie une requête GET "/page"
    Then le WAF sert la page de challenge

  Scenario: Challenge JS réussi — cookie émis et redirect
    Given un visiteur a reçu la page de challenge avec un token valide
    When le JavaScript exécute le proof-of-work (elapsed_ms = 1200)
    And soumet POST /waf/verify avec:
      | token         | <token_valide>            |
      | nonce         | "4837291"                 |
      | elapsed_ms    | 1200                      |
      | fingerprint   | <fingerprint_navigateur>  |
    Then le WAF retourne HTTP 200
    And la réponse contient { "redirect_url": "/page" }
    And la réponse inclut Set-Cookie "waf_session=<cookie_signé>; HttpOnly; SameSite=Lax; Max-Age=86400"
    And le score du visiteur est incrémenté de 25
    And le visiteur est redirigé vers "/page"

  Scenario: Requête suivante avec cookie valide — pas de challenge
    Given un visiteur avec un cookie waf_session valide
    When il envoie une requête GET "/autre-page"
    Then le WAF valide le cookie (HMAC + TTL + ip_hash)
    And la requête est transmise à l'upstream sans interruption
    And la latence ajoutée est < 5 ms

  Scenario: Token de challenge expiré (> 30s)
    Given un visiteur a reçu la page de challenge il y a 45 secondes
    When il soumet POST /waf/verify avec le token expiré
    Then le WAF retourne HTTP 400
    And la réponse contient {"error": "token_expired"}
    And une nouvelle page de challenge est servie automatiquement

  Scenario: Proof-of-work invalide
    Given un visiteur soumet POST /waf/verify avec un nonce incorrect
    Then le WAF retourne HTTP 400
    And la réponse contient {"error": "invalid_pow"}
    And le score du visiteur est décrémenté de 20

  Scenario: Challenge trop rapide (bot)
    Given un visiteur soumet POST /waf/verify avec elapsed_ms = 50
    Then le WAF retourne HTTP 400
    And la réponse contient {"error": "challenge_too_fast"}
    And le score du visiteur est décrémenté de 20

  Scenario: Challenge trop lent (timeout côté client)
    Given un visiteur soumet POST /waf/verify avec elapsed_ms = 15000
    Then le WAF retourne HTTP 400
    And la réponse contient {"error": "challenge_timeout"}

  Scenario: Cookie falsifié (HMAC invalide)
    Given un visiteur envoie une requête avec un cookie waf_session forgé
    When le WAF tente de valider le cookie
    Then la validation HMAC échoue
    And le WAF sert la page de challenge
    And un événement de sécurité est journalisé avec reason="invalid_cookie_signature"

  Scenario: Cookie expiré
    Given un visiteur avec un cookie waf_session émis il y a 25h (TTL = 24h)
    When il envoie une requête
    Then le WAF sert la page de challenge
    And aucun événement de sécurité anormal n'est journalisé

  Scenario: URL de retour préservée après challenge
    Given un visiteur sans cookie demande GET "/articles/mon-article?ref=newsletter"
    When il passe le challenge avec succès
    Then il est redirigé vers "/articles/mon-article?ref=newsletter" (URL originale complète)

  Scenario: Page challenge — branding et chronomètre présents
    When le WAF sert la page de challenge
    Then la page contient le texte "Protected by GaetanDev.fr"
    And la page contient un lien vers "https://firewall.gaetandev.fr"
    And la page contient un élément chronomètre visible
    And la page contient l'animation CSS "moveBackground"
    And la page ne charge aucune ressource externe (pas de CDN)
