Feature: Bypass des Assets Statiques
  En tant que WAF,
  Je veux bypasser les middlewares de sécurité pour les ressources statiques
  Afin de ne pas dégrader les performances et ne jamais challenger pour du CSS, JS, ou images.

  Background:
    Given le WAF est configuré avec les extensions statiques par défaut:
      [.css, .js, .map, .png, .jpg, .jpeg, .gif, .webp, .svg, .ico, .woff, .woff2, .ttf, .eot]
    And les paths statiques: [/static/, /assets/, /public/, /dist/]
    And les paths exacts: [/favicon.ico, /robots.txt, /sitemap.xml]

  Scenario: Requête CSS — bypass total des middlewares de sécurité
    Given un nouveau visiteur sans cookie (score = 50, sous le challenge threshold)
    When il envoie GET "/styles/main.css"
    Then la requête est proxifiée directement sans challenge
    And aucune page de challenge n'est servie
    And aucun score de confiance n'est calculé

  Scenario: Requête JS — même comportement
    Given un visiteur avec score = 25 (normalement challengé)
    When il envoie GET "/js/app.bundle.js"
    Then la requête est proxifiée sans challenge
    Note: Le JS doit charger pour que le challenge lui-même fonctionne

  Scenario: Image — bypass
    Given n'importe quel visiteur
    When il envoie GET "/images/logo.png"
    Then la requête est proxifiée immédiatement

  Scenario: Font — bypass
    When GET "/fonts/roboto.woff2"
    Then la requête est proxifiée immédiatement

  Scenario: Favicon — bypass
    When GET "/favicon.ico"
    Then la requête est proxifiée immédiatement

  Scenario: robots.txt — bypass
    When GET "/robots.txt"
    Then la requête est proxifiée immédiatement (nécessaire pour les moteurs de recherche)

  Scenario: sitemap.xml — bypass
    When GET "/sitemap.xml"
    Then la requête est proxifiée immédiatement

  Scenario: Path /assets/ — bypass par préfixe
    When GET "/assets/vendor/react.min.js"
    Then la requête est proxifiée immédiatement

  Scenario: IP en blacklist — pas de bypass même pour un asset
    Given l'IP "1.2.3.4" est en blacklist
    When elle demande GET "/styles/main.css"
    Then la requête reçoit HTTP 403 (blacklist > bypass assets)
    Note: La blacklist s'applique toujours, même pour les assets

  Scenario: Bypass n'inclut pas le rate limit pour les IPs normales
    Given un visiteur avec score = 75 en bypass asset
    When il envoie 500 requêtes d'assets en 10 secondes
    Then les requêtes d'assets sont comptées dans le rate limit global
    And si le rate limit est déclenché → 429 (même pour les assets)
    Note: Le bypass concerne challenge + trust score, pas le rate limit

  Scenario: Extension ambiguë — traitement comme non-asset (sécurité > perf)
    Given une requête GET "/api/data.json"
    And ".json" n'est pas dans la liste des extensions d'assets
    When le WAF traite la requête
    Then le pipeline sécurité complet s'applique
    Note: .json peut être de l'API dynamique, pas un asset

  Scenario: Extension configurable — ajout de .pdf
    Given l'administrateur ajoute ".pdf" à la liste des extensions statiques
    When GET "/documents/brochure.pdf"
    Then la requête est proxifiée sans challenge

  Scenario: Métriques assets vs requêtes normales
    When GET /waf/metrics
    Then les métriques contiennent:
      | waf_asset_requests_total        | total requêtes assets      |
      | waf_requests_total{type="page"} | total requêtes non-assets  |
    Et le ratio assets/total est visible pour ajuster la config

  Scenario: Source Map bypass — .map traité comme asset
    When GET "/js/app.bundle.js.map"
    Then la requête est proxifiée sans challenge
    Note: Les source maps peuvent être sensibles, mais bloquer cause des erreurs dev
    Note: Recommandation : ne pas exposer .map en production (responsabilité de l'app)
