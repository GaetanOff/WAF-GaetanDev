Feature: Analyse Comportementale Séquentielle
  En tant que WAF,
  Je veux analyser les patterns de navigation des visiteurs
  Afin de détecter les bots qui ont passé le challenge JS mais se comportent de manière anormale.

  Background:
    Given le WAF est configuré avec behavioral.enabled = true
    And behavioral.window_size = 50

  Scenario: Visiteur humain — intervalles variables détectés
    Given un visiteur avec cookie valide (score = 75)
    When il effectue 10 requêtes avec des intervalles de: 3s, 8s, 2s, 15s, 4s, 22s, 1s, 9s, 5s, 12s
    Then le signal time_uniformity est bas (écart-type élevé)
    And le anomaly_score est < 20
    And le trust score n'est pas diminué

  Scenario: Bot — intervalles uniformes (boucle sleep)
    Given un visiteur avec cookie valide (score = 75)
    When il effectue 15 requêtes avec des intervalles de 500ms ± 20ms
    Then le signal time_uniformity est élevé (écart-type < 50ms)
    And le anomaly_score augmente de +30 pour ce signal
    And le trust score est décrémenté de 20 (anomaly_score > 70)

  Scenario: Scraper — même path répété
    Given un visiteur effectue les requêtes: GET /api/products, GET /api/products, GET /api/products, GET /api/products (4 fois)
    When l'analyste calcule le signal path_repetition
    Then le ratio de répétition est 4/4 = 1.0 (100%)
    And le anomaly_score augmente de +40 pour ce signal

  Scenario: Crawler — vélocité de découverte élevée
    Given un visiteur qui visite 40 paths uniques en 60 secondes
    When l'analyseur calcule le signal page_velocity
    Then le anomaly_score augmente de +35 pour ce signal
    And le visiteur passe en état CHALLENGED si son trust_score descend sous le seuil

  Scenario: Crawler — ordre alphabétique détecté
    Given un visiteur effectue les requêtes: GET /articles/art, GET /articles/bbb, GET /articles/ccc, GET /articles/ddd, GET /articles/eee
    When l'analyseur vérifie l'ordre alphabétique sur 5 paths consécutifs
    Then le signal alpha_order est déclenché
    And le anomaly_score augmente de +25

  Scenario: Headless sans assets — absence de CSS/JS
    Given un visiteur effectue 20 requêtes
    And seulement 1 d'entre elles concerne un asset (CSS/JS/image)
    When l'analyseur calcule le ratio assets (1/20 = 5%)
    Then le signal asset_absence est élevé
    And le anomaly_score augmente de +20

  Scenario: Bot sophistiqué — combinaison de signaux
    Given un visiteur avec cookie valide (score = 70)
    When il déclenche simultanément:
      | Signal           | Score signal |
      | time_uniformity  | 50           |
      | path_repetition  | 30           |
      | page_velocity    | 40           |
      | asset_absence    | 20           |
    Then l'anomaly_score composite est environ 60 (pondéré par weights)
    And le trust score est décrémenté de 20 (anomaly > 70 non atteint ici)

  Scenario: Analyse asynchrone — ne bloque pas la requête
    Given un visiteur envoie une requête
    When l'analyse comportementale est en cours de calcul
    Then la requête courante est traitée sans attendre le résultat de l'analyse
    And le résultat de l'analyse est appliqué à la PROCHAINE requête

  Scenario: Channel plein — événements droppés sans blocage
    Given le channel d'analyse comportementale est saturé (1000 événements en attente)
    When un nouveau visiteur envoie une requête
    Then l'événement comportemental est droppé silencieusement
    And la requête est traitée normalement (pas de blocage)
    And une métrique waf_behavioral_events_dropped_total est incrémentée

  Scenario: Classification finale
    Given un visiteur avec anomaly_score = 85
    Then il est classifié comme "likely_bot"
    And ce classement est visible dans GET /waf/admin/visitors/{ip_hash}

  Scenario: Ring buffer — fenêtre glissante
    Given un visiteur a accumulé 50 requêtes (buffer plein)
    When il envoie sa 51ème requête
    Then la requête la plus ancienne est supprimée du buffer
    And l'analyse porte toujours sur les 50 requêtes les plus récentes
