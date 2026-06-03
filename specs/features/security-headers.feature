Feature: Security Headers & Response Sanitization
  En tant que WAF,
  Je veux injecter des security headers dans les réponses et masquer les informations d'infrastructure
  Afin de protéger les utilisateurs contre les attaques côté client et de cacher la stack technique.

  Background:
    Given le WAF est configuré avec security_headers.enabled = true

  # ── Security Headers Injection ──────────────────────────────────────────────

  Scenario: Headers de sécurité injectés sur réponse upstream normale
    Given l'upstream retourne HTTP 200 sans aucun security header
    When le WAF transmet la réponse au client
    Then la réponse contient les headers suivants:
      | Header                    | Valeur par défaut                         |
      | Strict-Transport-Security | max-age=31536000; includeSubDomains        |
      | X-Frame-Options           | SAMEORIGIN                                |
      | X-Content-Type-Options    | nosniff                                   |
      | Referrer-Policy           | strict-origin-when-cross-origin           |
      | X-XSS-Protection          | 1; mode=block                             |
      | X-WAF-Protected           | GaetanDev.fr/1.0                          |

  Scenario: Upstream a déjà X-Frame-Options — WAF ne l'écrase pas
    Given l'upstream envoie "X-Frame-Options: DENY"
    When le WAF traite la réponse
    Then le client reçoit "X-Frame-Options: DENY" (valeur upstream)
    And le WAF n'a pas écrasé ni dupliqué le header

  Scenario: CSP non injectée par défaut
    Given security_headers.content_security_policy = "" (vide)
    When le WAF transmet une réponse
    Then le header Content-Security-Policy n'est PAS présent

  Scenario: CSP configurée par domaine
    Given pour le domaine "example.com":
      security_headers.content_security_policy = "default-src 'self'; script-src 'self' cdn.example.com"
    When le WAF transmet une réponse pour example.com
    Then le client reçoit le header Content-Security-Policy avec cette valeur

  Scenario: HSTS uniquement sur HTTPS (pas sur HTTP)
    Given le client se connecte via HTTP (non sécurisé)
    When le WAF transmet la réponse
    Then Strict-Transport-Security n'est PAS injecté (inutile et trompeur en HTTP)

  Scenario: Security headers désactivés par domaine
    Given pour le domaine "api.example.com": security_headers.enabled = false
    When une réponse est transmise pour ce domaine
    Then aucun security header n'est injecté par le WAF

  Scenario: Header X-WAF-Protected désactivé (whitelabel)
    Given security_headers.x_waf_protected = "" (vide)
    When le WAF transmet la réponse
    Then le header X-WAF-Protected n'est pas présent

  # ── Response Sanitization ───────────────────────────────────────────────────

  Scenario: Header Server masqué
    Given l'upstream retourne "Server: nginx/1.25.3"
    And sanitize_response_headers.enabled = true
    When le WAF transmet la réponse
    Then le header Server est absent de la réponse client
    Ou bien remplacé par la valeur configurable "Server: WAF/1.0"

  Scenario: Headers X-Powered-By et X-Generator supprimés
    Given l'upstream retourne:
      | X-Powered-By: PHP/8.2.0           |
      | X-Generator: WordPress 6.4        |
    When le WAF transmet la réponse
    Then ces headers sont absents de la réponse client

  Scenario: Header Via supprimé (cache les proxies intermédiaires)
    Given la chaîne de proxy ajoute "Via: 1.1 nginx"
    When le WAF transmet la réponse
    Then le header Via est supprimé

  Scenario: Masquage des erreurs 5xx avec stack trace
    Given sanitize_errors.enabled = true
    And l'upstream retourne HTTP 500 avec un body contenant:
      "/var/www/html/application/controllers/UserController.php line 42: Undefined variable"
    When le WAF transmet la réponse
    Then le body est remplacé par la page d'erreur générique configurée
    And le status code reste 500

  Scenario: Erreurs 5xx sans stack trace — passées en clair
    Given l'upstream retourne HTTP 503 avec body "Service temporarily unavailable"
    And ce body ne contient pas de chemin de fichier ou stack trace
    When le WAF transmet la réponse
    Then le body est transmis tel quel (pas de remplacement)

  Scenario: Latence de sanitisation
    When le WAF applique la sanitisation sur une réponse
    Then le délai de traitement de la sanitisation est < 0.5ms
