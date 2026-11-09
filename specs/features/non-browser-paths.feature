Feature: Chemins non-navigateur par domaine (FR-41)
  En tant qu'opérateur d'une API appelée serveur à serveur,
  Je veux que ses chemins ne soient pas pénalisés pour l'absence d'en-têtes navigateur
  Afin que les backends intégrateurs ne soient pas bloqués, sans ouvrir de contournement.

  # Spec : requirements-ops.md FR-41 ; décision : ADR-023 ;
  # schéma : config.schema.json (DomainConfig.non_browser_paths).
  # Tests : internal/middleware/antibot (couche anti-bot), internal/config
  # (validation, cohérence schéma ↔ Go), cmd/waf (pipeline complet).

  Background:
    Given le WAF est opérationnel avec la configuration par défaut
    And le score initial pour tout nouveau visiteur est 50
    And le seuil de blocage est 10
    And l'entrée domains[] "captcha.example.com" déclare challenge_enabled false
    And elle déclare non_browser_paths ["/v1/", "/webhook"]

  # --- Happy paths ---

  Scenario: Appels serveur répétés sur un préfixe exempté
    Given un client à l'IP "203.0.113.7" avec User-Agent "node"
    And la requête ne contient ni "Accept-Language" ni "Accept-Encoding"
    When il envoie 100 requêtes POST "/v1/siteverify" sur "captcha.example.com"
    Then aucune requête ne reçoit de réponse 403 de l'anti-bot
    And le score du visiteur reste 50
    And aucune contribution de risque fingerprint n'est publiée
    And waf_antibot_non_browser_exempt_total{domain="captcha.example.com"} vaut 100

  Scenario Outline: Signaux non-navigateur neutralisés
    Given une requête POST "/v1/siteverify" sur "captcha.example.com" avec <condition>
    When le WAF analyse la requête
    Then le score du visiteur n'est pas modifié
    And la requête est transmise à l'upstream

    Examples:
      | condition                                   |
      | un User-Agent vide                          |
      | le User-Agent "python-requests/2.32.0"      |
      | le User-Agent "curl/8.5.0"                  |
      | le User-Agent "Go-http-client/2.0"          |
      | le User-Agent "GuzzleHttp/7" sans Accept-*  |

  Scenario: Motif exact
    Given une requête POST "/webhook" sur "captcha.example.com" avec User-Agent "curl/8.5.0"
    When le WAF analyse la requête
    Then le score du visiteur n'est pas modifié

  Scenario: Hôte avec casse et port différents
    Given une requête POST "/v1/siteverify" sur "Captcha.Example.com:443" avec User-Agent "node"
    And la requête ne contient pas "Accept-Language"
    When le WAF analyse la requête
    Then le score du visiteur n'est pas modifié

  Scenario: Wildcard couvrant l'hôte et son apex
    Given l'entrée domains[] "*.api.example.com" déclare non_browser_paths ["/v1/"]
    When une requête POST "/v1/x" arrive sur "eu.api.example.com" avec User-Agent "curl/8.5.0"
    And une requête POST "/v1/x" arrive sur "api.example.com" avec User-Agent "curl/8.5.0"
    Then le score du visiteur n'est pas modifié
    And waf_antibot_non_browser_exempt_total{domain="*.api.example.com"} vaut 2

  # --- Hors périmètre : la pénalité s'applique toujours ---

  Scenario Outline: Chemin non couvert
    Given une requête GET "<path>" sur "captcha.example.com" avec User-Agent "curl/8.5.0"
    When le WAF analyse la requête
    Then le score du visiteur est décrémenté de 15

    Examples:
      | path           |
      | /              |
      | /v1            |
      | /v10/x         |
      | /V1/siteverify |
      | /webhook/x     |

  Scenario: Autre domaine sans non_browser_paths
    Given une requête POST "/v1/siteverify" sur "www.example.com" avec User-Agent "curl/8.5.0"
    When le WAF analyse la requête
    Then le score du visiteur est décrémenté de 15

  Scenario: Pas d'héritage depuis un wildcard placé après
    Given l'entrée domains[] "api.example.com" sans non_browser_paths précède "*.example.com"
    And l'entrée "*.example.com" déclare non_browser_paths ["/v1/"]
    When une requête POST "/v1/x" arrive sur "api.example.com" avec User-Agent "curl/8.5.0"
    Then le score du visiteur est décrémenté de 15

  # --- Error paths : pas de contournement ---

  Scenario Outline: Chemin non canonique jamais exempté
    Given une requête GET "<path>" sur "captcha.example.com" avec User-Agent "curl/8.5.0"
    When le WAF analyse la requête
    Then aucune exemption FR-41 n'est appliquée
    And le score du visiteur est décrémenté de 15
    And waf_antibot_non_browser_exempt_total n'est pas incrémenté

    Examples:
      | path             |
      | /v1/../admin     |
      | /v1/./siteverify |
      | /v1//siteverify  |

  Scenario: Honeypot toujours bloquant sous un chemin exempté
    Given "/v1/.env" figure dans honeypot_paths
    When un client envoie GET "/v1/.env" sur "captcha.example.com"
    Then la requête reçoit une réponse HTTP 403
    And le visiteur est banni pendant trust.score_ttl

  Scenario: UA d'automatisation toujours bloqué
    Given une requête POST "/v1/siteverify" avec User-Agent "Mozilla/5.0 puppeteer"
    When le WAF analyse la requête
    Then la requête reçoit une réponse HTTP 403
    And le log indique reason="automation_user_agent"

  Scenario: Navigateur headless toujours pénalisé
    Given une requête POST "/v1/siteverify" avec User-Agent "HeadlessChrome/120.0"
    When le WAF analyse la requête
    Then le score du visiteur est décrémenté de 30

  Scenario: Visiteur déjà BLOCKED reste bloqué
    Given le visiteur "203.0.113.9" est banni sur "captcha.example.com" par le honeypot
    When il envoie POST "/v1/siteverify" avec User-Agent "node"
    Then la requête reçoit une réponse HTTP 403

  Scenario: Rate limiting toujours appliqué
    Given rate_limit.burst vaut 100
    When un client envoie 150 requêtes POST "/v1/siteverify" en une seconde
    Then au moins une requête reçoit une réponse HTTP 429 avec Retry-After

  Scenario: Blacklist IP toujours appliquée
    Given l'IP "198.51.100.1" est dans blacklist
    When elle envoie POST "/v1/siteverify" sur "captcha.example.com"
    Then la requête reçoit une réponse HTTP 403

  # --- Validation de configuration ---

  Scenario Outline: Motif invalide refusé au démarrage
    Given l'entrée domains[0] déclare non_browser_paths [<motif>]
    When le WAF valide sa configuration
    Then le démarrage échoue
    And l'erreur cite "domains[0].non_browser_paths"

    Examples:
      | motif       |
      | "v1/"       |
      | "/"         |
      | ""          |
      | "/v1/*"     |
      | "/v1/../x/" |
      | "//v1/"     |
      | "/v1/?a=b"  |

  Scenario: Doublon refusé
    Given l'entrée domains[0] déclare non_browser_paths ["/v1/", "/v1/"]
    When le WAF valide sa configuration
    Then le démarrage échoue

  Scenario: Plus de 32 motifs refusés
    Given l'entrée domains[0] déclare 33 motifs non_browser_paths distincts
    When le WAF valide sa configuration
    Then le démarrage échoue
    And l'erreur cite "must not exceed 32 entries"

  Scenario: Clé absente — comportement inchangé
    Given aucune entrée domains[] ne déclare non_browser_paths
    When une requête POST "/v1/siteverify" arrive avec User-Agent "curl/8.5.0"
    Then le score du visiteur est décrémenté de 15
