Feature: Règles Géographiques
  En tant qu'administrateur du WAF,
  Je veux appliquer des règles différentes selon le pays d'origine du visiteur
  Afin d'adapter la protection aux risques géographiques réels.

  # Contrat : bloc `geo` de config.schema.json (enabled, allowed_countries,
  # blocked_countries, challenge_countries, challenge_contribution), FR-16.
  # Les scénarios @deferred sont spécifiés mais NON implémentés (audit du
  # 2026-09-24, point 4.1) : ils ne sont pas un critère d'acceptation tant que
  # leur implémentation n'est pas planifiée (specs/tasks.md). Ils décrivaient un
  # bloc `geo_rules:` qui n'a jamais existé dans le contrat de configuration.

  Background:
    Given geo.enabled = true
    And le WAF reçoit des requêtes avec le header CF-IPCountry fourni par Cloudflare

  Scenario: Blocage total d'un pays
    Given geo.blocked_countries = ["KP"]
    When une requête avec CF-IPCountry: KP arrive
    Then la requête reçoit HTTP 403 avec X-WAF-Action: BLOCK
    And le log indique reason="geo_country_blocked"

  Scenario: Challenge d'un pays à risque — contribution au moteur de risque
    Given geo.challenge_countries = ["CN", "RU", "IR"]
    And geo.challenge_contribution = 60
    When une requête avec CF-IPCountry: RU arrive
    Then la requête porte X-WAF-Risk-geo: 60 et reason="geo_country_challenge"
    And le moteur de risque fusionne cette contribution de la famille geo
    And seule, cette famille ne peut pas produire de BLOCK, au plus un CHALLENGE (FR-35)
    # Sans moteur de risque (risk_engine.enabled: false), la contribution n'est
    # lue par personne : challenge_countries n'a alors pas d'effet.

  Scenario: Whitelist de pays — seuls ces pays autorisés
    Given geo.allowed_countries = ["FR", "BE", "CH", "CA"]
    When une requête avec CF-IPCountry: DE (Allemagne, non listé) arrive
    Then la requête reçoit HTTP 403 avec reason="geo_country_not_allowed"
    When une requête avec CF-IPCountry: FR (France, listé) arrive
    Then la requête est traitée normalement

  Scenario: Header CF-IPCountry absent — règles geo ignorées
    Given le WAF est déployé sans Cloudflare en front
    And le header CF-IPCountry n'est pas présent
    When une requête arrive
    Then les règles géographiques sont ignorées
    And aucune erreur n'est journalisée (comportement gracieux)

  # ADR-019 option B : la forge d'un CF-* est ramenée à son omission.
  Scenario: CF-IPCountry forgé hors Cloudflare — supprimé et ignoré
    Given cloudflare.trusted = true
    And geo.blocked_countries = ["RU"]
    And une connexion directe depuis 203.0.113.10 (hors plages Cloudflare)
    When elle envoie une requête avec CF-IPCountry: FR
    Then l'en-tête CF-IPCountry est supprimé avant les règles géographiques et le proxy
    And les règles géographiques sont ignorées comme pour un en-tête absent
    And la requête n'est pas rejetée pour autant

  Scenario: cloudflare.trusted = false — aucun CF-* n'est honoré
    Given cloudflare.trusted = false
    When le WAF démarre
    Then un avertissement signale que les règles géographiques n'ont aucune entrée
    When une requête arrive avec CF-IPCountry: RU depuis une plage Cloudflare
    Then l'en-tête est supprimé et la requête n'est pas bloquée par la géo

  Scenario: Code pays inconnu — traité comme tout autre code
    Given geo.blocked_countries = ["RU"] et aucune liste allowed_countries
    When une requête avec CF-IPCountry: XX (code inconnu de Cloudflare) arrive
    Then la requête est traitée sans règle geo spécifique
    And le code est comparé aux listes sans tenir compte de la casse ni des espaces
    # Avec allowed_countries, un code inconnu n'est pas listé : il est refusé.

  @deferred
  Scenario: Journal debug d'un code pays inconnu
    Given une requête avec CF-IPCountry: XX (code inconnu)
    When le WAF traite la règle geo
    Then un log debug indique "unknown country code: XX"

  @deferred
  Scenario: Rate limit renforcé par pays
    Given un rate limit dédié de 10 req/s (burst 20) pour le pays BR
    When un visiteur du Brésil envoie 25 requêtes en 1 seconde
    Then les 20 premières sont transmises (burst)
    And les suivantes reçoivent 429

  @deferred
  Scenario: Score delta initial par pays
    Given un delta de score initial de -15 pour les pays CN et RU
    When un nouveau visiteur de Chine arrive (score initial = 50)
    Then son score initial est 35 (50 - 15)
    And il reçoit le challenge immédiatement si 35 < challenge_threshold

  @deferred
  Scenario: Règles geo par domaine (override)
    Given pour le domaine "api.example.com" seuls US et FR sont autorisés
    When une requête pour api.example.com vient d'Espagne (ES)
    Then HTTP 403 est retourné
    When la même IP accède à "www.example.com" (pas de règle geo)
    Then la requête passe normalement

  @deferred
  Scenario: Métriques par pays
    When GET /waf/metrics
    Then les métriques contiennent waf_requests_total{country="FR"}
    And waf_blocked_total{reason="geo_country_blocked", country="KP"}
    # Les métriques n'ont aujourd'hui aucun label country ; un blocage géo est
    # compté dans waf_blocked_total{domain, reason="geo_country_blocked"}.
