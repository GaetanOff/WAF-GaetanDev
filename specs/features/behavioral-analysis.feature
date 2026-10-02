Feature: Analyse Comportementale Séquentielle
  En tant que WAF,
  Je veux analyser les patterns de navigation des visiteurs
  Afin de signaler au moteur de risque les bots qui ont passé le challenge JS mais se comportent de manière anormale.

  # Contrat : FR-12 (requirements-advanced.md), réaligné sur le code le
  # 2026-10-02. Le score est la contribution "behavioral" du moteur de risque
  # (FR-33) ; il n'agit pas sur le trust score. Les scénarios @deferred sont
  # spécifiés mais NON implémentés.

  Background:
    Given le WAF est configuré avec behavioral.enabled = true
    And behavioral.max_records = 50

  Scenario: Visiteur humain — intervalles variables
    Given un visiteur qui charge 10 pages avec des intervalles de: 3s, 8s, 2s, 15s, 4s, 22s, 1s, 9s, 5s, 12s
    And il charge les assets de chaque page
    When l'analyseur calcule le score
    Then le signal d'uniformité temporelle n'est pas déclenché
    And aucune contribution "behavioral" n'est publiée

  Scenario: Bot — intervalles uniformes (boucle sleep)
    Given un visiteur qui charge 15 pages à 500 ms ± 20 ms d'intervalle
    When l'analyseur calcule le score
    Then le signal d'uniformité temporelle est déclenché (coefficient de variation < 0,1)
    And la contribution "behavioral" vaut au moins 30

  Scenario: Scraper — même path répété
    Given un visiteur qui demande GET /api/products 11 fois consécutives
    When l'analyseur calcule le score
    Then le signal de répétition est déclenché
    And il apporte 25 à la contribution "behavioral"

  Scenario: Crawler — vélocité de découverte élevée
    Given un visiteur qui visite 20 paths uniques en moins de 5 secondes
    When l'analyseur calcule le score
    Then le signal de vélocité apporte 25 à la contribution "behavioral"

  Scenario: Crawler — ordre alphabétique détecté
    Given un visiteur effectue les requêtes: GET /articles/aaa, GET /articles/bbb, GET /articles/ccc, GET /articles/ddd, GET /articles/eee
    When l'analyseur vérifie l'ordre des paths uniques
    Then le signal d'ordre alphabétique apporte 20 à la contribution "behavioral"

  Scenario: Headless sans assets — absence de CSS/JS
    Given un visiteur charge 5 pages sans aucune requête d'asset
    When l'analyseur calcule le score
    Then le signal d'absence d'assets apporte 20 à la contribution "behavioral"
    # Faux positif connu : un CDN qui sert les assets depuis son cache.

  Scenario: Humain chargeant ses assets — les assets bypassés comptent
    Given static_assets.enabled = true (les assets sont marqués PASS en amont)
    And un visiteur navigue sur 6 pages en chargeant le CSS/JS de chaque page
    When l'analyseur calcule le score
    Then les requêtes d'assets marquées PASS "static_asset" sont enregistrées
    And le signal d'absence d'assets n'est PAS déclenché
    And les rafales d'assets n'entrent pas dans l'uniformité, la vélocité ni l'ordre alphabétique
    # Régression : sans cet enregistrement, tout humain ayant vu 5 pages recevait +20
    # (les assets PASS n'étaient jamais observés par l'analyseur).

  Scenario: Signaux combinés — somme bornée
    Given un visiteur qui déclenche l'uniformité (30), la répétition (25), la vélocité (25) et l'absence d'assets (20)
    When l'analyseur calcule le score
    Then la contribution "behavioral" vaut 100 (somme bornée)
    And le moteur de risque décide de la mitigation (FR-33)

  Scenario: Moins de 5 pages — aucun score
    Given un visiteur n'a chargé que 4 pages
    When l'analyseur calcule le score
    Then aucune contribution "behavioral" n'est publiée

  Scenario: Analyse asynchrone — ne bloque pas la requête
    Given un visiteur envoie une requête
    When l'analyse comportementale est en cours de calcul
    Then la requête courante est traitée sans attendre le résultat de l'analyse
    And le résultat de l'analyse est publié sur la PROCHAINE requête

  Scenario: Channel plein — événements droppés sans blocage
    Given le channel d'analyse comportementale est saturé (1024 événements en attente)
    When un nouveau visiteur envoie une requête
    Then l'événement comportemental est droppé silencieusement
    And la requête est traitée normalement (pas de blocage)
    And une métrique waf_behavioral_events_dropped_total est incrémentée

  Scenario: Ring buffer — fenêtre glissante
    Given un visiteur a accumulé 50 requêtes (buffer plein)
    When il envoie sa 51ème requête
    Then la requête la plus ancienne est supprimée du buffer
    And l'analyse porte toujours sur les 50 requêtes les plus récentes

  @deferred
  Scenario: Anomalie élevée — pénalité de trust score
    Given un visiteur avec un anomaly_score > 70
    Then le trust score est décrémenté de 20

  @deferred
  Scenario: Classification finale
    Given un visiteur avec anomaly_score = 85
    Then il est classifié comme "likely_bot"
    And ce classement est visible dans GET /waf/admin/visitors/{ip_hash}
    # VisitorInfo (admin.openapi.yaml) ne porte aucune classification ; seul le
    # score X-WAF-Risk-Behavioral est publié au moteur de risque.
