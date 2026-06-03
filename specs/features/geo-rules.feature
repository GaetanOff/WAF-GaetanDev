Feature: Règles Géographiques
  En tant qu'administrateur du WAF,
  Je veux appliquer des règles différentes selon le pays d'origine du visiteur
  Afin d'adapter la protection aux risques géographiques réels.

  Background:
    Given le WAF reçoit des requêtes avec le header CF-IPCountry fourni par Cloudflare

  Scenario: Blocage total d'un pays
    Given la configuration:
      geo_rules:
        - countries: ["KP"]
          action: block
    When une requête avec CF-IPCountry: KP arrive
    Then la requête reçoit HTTP 403
    And le log indique reason="geo_block" country="KP"

  Scenario: Challenge systématique pour un pays à risque
    Given la configuration:
      geo_rules:
        - countries: ["CN", "RU", "IR"]
          action: challenge_always
    Given un visiteur de Russie (CF-IPCountry: RU) avec score = 80
    When il envoie une requête
    Then le challenge JS est déclenché malgré un score élevé (override du threshold)

  Scenario: Rate limit renforcé par pays
    Given la configuration:
      geo_rules:
        - countries: ["BR"]
          rate_limit_override:
            requests_per_second: 10
            burst: 20
    When un visiteur du Brésil envoie 25 requêtes en 1 seconde
    Then les 20 premières sont transmises (burst)
    And les suivantes reçoivent 429

  Scenario: Score delta initial par pays
    Given la configuration:
      geo_rules:
        - countries: ["CN", "RU"]
          score_delta: -15
    When un nouveau visiteur de Chine arrive (score initial = 50)
    Then son score initial est 35 (50 - 15)
    And il reçoit le challenge immédiatement si 35 < challenge_threshold

  Scenario: Whitelist de pays — seuls ces pays autorisés
    Given la configuration:
      geo_rules:
        - allowed_countries: ["FR", "BE", "CH", "CA"]
          action: block_others
    When une requête avec CF-IPCountry: DE (Allemagne, non listé)
    Then la requête reçoit HTTP 403
    When une requête avec CF-IPCountry: FR (France, listé)
    Then la requête est traitée normalement

  Scenario: Règles geo par domaine (override)
    Given pour le domaine "api.example.com":
      geo_rules:
        - countries: ["US", "FR"]
          action: allow_only
    When une requête pour api.example.com vient d'Espagne (ES)
    Then HTTP 403 est retourné
    When la même IP accède à "www.example.com" (pas de règle geo)
    Then la requête passe normalement

  Scenario: Header CF-IPCountry absent — règles geo ignorées
    Given le WAF est déployé sans Cloudflare en front
    And le header CF-IPCountry n'est pas présent
    When une requête arrive
    Then les règles géographiques sont ignorées
    And aucune erreur n'est journalisée (comportement gracieux)

  Scenario: Code pays inconnu — traitement par défaut
    Given une requête avec CF-IPCountry: XX (code inconnu)
    When le WAF traite la règle geo
    Then la requête est traitée sans règle geo spécifique
    And un log debug indique "unknown country code: XX"

  Scenario: Métriques par pays
    When GET /waf/metrics
    Then les métriques contiennent waf_requests_total{country="FR"}
    And waf_requests_blocked_total{reason="geo_block", country="KP"}
