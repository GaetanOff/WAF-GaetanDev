Feature: Security Headers & Response Sanitization
  En tant que WAF,
  Je veux injecter des security headers dans les réponses et masquer les informations d'infrastructure
  Afin de protéger les utilisateurs contre les attaques côté client et de cacher la stack technique.

  # Contrat : bloc security_headers de config.schema.json (FR-21, FR-22).
  # Les scénarios @deferred sont spécifiés mais NON implémentés (audit du
  # 2026-09-30) : ils ne sont pas un critère d'acceptation.

  Background:
    Given le WAF est configuré avec security_headers.enabled = true

  # ── Security Headers Injection ──────────────────────────────────────────────

  Scenario: Headers de sécurité injectés sur réponse upstream normale
    Given l'upstream retourne HTTP 200 sans aucun security header
    And security_headers garde ses valeurs par défaut
    When le WAF transmet la réponse au client
    Then la réponse contient les headers suivants:
      | Header                    | Valeur par défaut                         |
      | Strict-Transport-Security | max-age=31536000; includeSubDomains        |
      | X-Frame-Options           | DENY                                      |
      | X-Content-Type-Options    | nosniff                                   |
      | Referrer-Policy           | strict-origin-when-cross-origin           |
    And les headers Permissions-Policy et Content-Security-Policy sont absents (opt-in)

  Scenario: Upstream a déjà X-Frame-Options — WAF ne l'écrase pas
    Given l'upstream envoie "X-Frame-Options: SAMEORIGIN"
    When le WAF traite la réponse
    Then le client reçoit "X-Frame-Options: SAMEORIGIN" (valeur upstream)
    And le WAF n'a pas écrasé ni dupliqué le header

  Scenario: CSP non injectée par défaut
    Given security_headers.csp = "" (vide)
    When le WAF transmet une réponse
    Then le header Content-Security-Policy n'est PAS présent

  Scenario: CSP configurée globalement
    Given security_headers.csp = "default-src 'self'"
    When le WAF transmet une réponse sans CSP de l'upstream
    Then le client reçoit le header Content-Security-Policy avec cette valeur

  Scenario: HSTS injecté même si la connexion au WAF est en HTTP
    Given le WAF est derrière Cloudflare, qui termine le TLS du client
    And la connexion Cloudflare → WAF est en HTTP
    When le WAF transmet la réponse
    Then Strict-Transport-Security est injecté
    # Le client est en HTTPS ; un navigateur ignore HSTS reçu en HTTP clair.

  Scenario: HSTS désactivé
    Given security_headers.hsts_max_age = 0
    When le WAF transmet la réponse
    Then Strict-Transport-Security n'est PAS injecté

  @deferred
  Scenario: CSP configurée par domaine
    Given pour le domaine "example.com":
      security_headers.content_security_policy = "default-src 'self'; script-src 'self' cdn.example.com"
    When le WAF transmet une réponse pour example.com
    Then le client reçoit le header Content-Security-Policy avec cette valeur

  @deferred
  Scenario: Security headers désactivés par domaine
    Given pour le domaine "api.example.com": security_headers.enabled = false
    When une réponse est transmise pour ce domaine
    Then aucun security header n'est injecté par le WAF

  @deferred
  Scenario: X-XSS-Protection et signature X-WAF-Protected
    Given security_headers.x_xss_protection = "1; mode=block"
    And security_headers.x_waf_protected = "GaetanDev.fr/1.0"
    When le WAF transmet la réponse
    Then la réponse contient "X-XSS-Protection: 1; mode=block" et "X-WAF-Protected: GaetanDev.fr/1.0"
    And avec x_waf_protected = "" (whitelabel) le header X-WAF-Protected est absent

  # ── Response Sanitization ───────────────────────────────────────────────────

  Scenario: Header Server supprimé
    Given l'upstream retourne "Server: nginx/1.25.3"
    And security_headers.strip_headers contient "Server" (défaut)
    When le WAF transmet la réponse
    Then le header Server est absent de la réponse client

  Scenario: Headers révélateurs listés dans strip_headers supprimés
    Given security_headers.strip_headers = ["Server", "X-Powered-By", "X-Generator", "Via"]
    And l'upstream retourne:
      | X-Powered-By: PHP/8.2.0           |
      | X-Generator: WordPress 6.4        |
      | Via: 1.1 nginx                    |
    When le WAF transmet la réponse
    Then ces headers sont absents de la réponse client

  @deferred
  Scenario: Header Server remplacé par une valeur configurable
    Given l'upstream retourne "Server: nginx/1.25.3"
    When le WAF transmet la réponse
    Then le header Server vaut la valeur configurée "WAF/1.0"

  @deferred
  Scenario: Masquage des erreurs 5xx avec stack trace
    Given sanitize_errors.enabled = true
    And l'upstream retourne HTTP 500 avec un body contenant:
      "/var/www/html/application/controllers/UserController.php line 42: Undefined variable"
    When le WAF transmet la réponse
    Then le body est remplacé par la page d'erreur générique configurée
    And le status code reste 500
    # Implémenté aujourd'hui sans ciblage : maintenance.error_pages (FR-32)
    # remplace tout corps d'erreur texte d'une navigation par la page brandée.

  @deferred
  Scenario: Erreurs 5xx sans stack trace — passées en clair
    Given sanitize_errors.enabled = true
    And l'upstream retourne HTTP 503 avec body "Service temporarily unavailable"
    And ce body ne contient pas de chemin de fichier ou stack trace
    When le WAF transmet la réponse
    Then le body est transmis tel quel (pas de remplacement)

  Scenario: Latence de sanitisation
    When le WAF applique la sanitisation sur une réponse
    Then le délai de traitement de la sanitisation est < 0.5ms
