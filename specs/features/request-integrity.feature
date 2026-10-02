Feature: Analyse d'Intégrité des Requêtes
  En tant que WAF,
  Je veux détecter les requêtes malformées ou obfusquées
  Afin d'alimenter le moteur de risque face aux tentatives d'injection, de path traversal et d'exploitation.

  # Contrat : FR-18 (requirements-advanced.md), réaligné sur le code le
  # 2026-10-02. Les détections publient la famille "integrity" du moteur de
  # risque (FR-33) et ne bloquent pas ; seul le body trop grand est refusé.
  # Les scénarios @deferred sont spécifiés mais NON implémentés.

  Background:
    Given le WAF est configuré avec integrity.enabled = true
    And integrity.max_path_length = 2048
    And integrity.max_query_length = 4096
    And integrity.max_body_bytes = 10485760  # 10MB

  Scenario: Path traversal — séquence ../
    Given une requête GET "/pages/../../../etc/passwd"
    When le WAF analyse l'intégrité du path
    Then la contribution "integrity" publiée vaut 60
    And la raison journalisée est "path_traversal"
    And la requête est transmise au moteur de risque, qui décide

  Scenario: Path traversal — encodage URL double
    Given une requête GET "/pages/%252e%252e%252fetc%252fpasswd"
    When le WAF décode le path jusqu'à trois fois
    Then la séquence "../" est détectée après décodage
    And la contribution "integrity" publiée vaut 60

  Scenario: Null byte dans le path
    Given une requête GET "/page%00.html"
    When le WAF analyse le path
    Then la contribution "integrity" publiée vaut 60
    And la raison journalisée est "null_byte"

  Scenario: Path trop long
    Given une requête GET avec un path de 3000 caractères
    When le WAF vérifie la longueur du path
    Then la contribution "integrity" publiée vaut 25
    And la raison journalisée est "excessive_length"

  Scenario: Paramètre SQL injection pattern détecté
    Given une requête GET "/search?q=1%20UNION%20SELECT%20%2A%20FROM%20users"
    When le WAF analyse les query params
    Then la contribution "integrity" publiée vaut 40
    And la raison journalisée est "injection_pattern"
    And la requête n'est pas bloquée par l'analyse d'intégrité
    And aucun delta de trust score n'est appliqué

  Scenario: URL légitimes — pas de faux positif d'injection
    Given une requête GET vers l'une des URL suivantes :
      | /blog/my--first-post                 |
      | /docs?flags=--verbose                |
      | /search?q=please+select+your+size    |
      | /files/*/list                        |
    When le WAF analyse les query params
    Then aucun pattern d'injection n'est détecté
    And aucune contribution "integrity" n'est publiée
    # Régression : les sous-chaînes isolées "--", "select " et "/*" ajoutaient +40.
    # Le commentaire SQL n'est retenu que derrière une quote ("'--").

  Scenario: Paramètre XSS pattern détecté
    Given une requête GET "/page?name=<script>alert(1)</script>"
    When le WAF analyse les query params
    Then la contribution "integrity" publiée vaut 40

  Scenario: Détections cumulées et bornées
    Given une requête GET dont le path contient "../" et "%00"
    When le WAF analyse l'intégrité
    Then la contribution "integrity" publiée vaut 100 (60 + 60, bornée)

  Scenario: Body trop grand — rejet
    Given une requête POST avec un body de 15MB (> 10MB limit)
    When le WAF vérifie la taille du body
    Then la requête reçoit HTTP 413 (Content Too Large)
    And la connexion upstream n'est pas ouverte
    And l'événement de sécurité porte action = "BLOCK" et reason = "body_too_large"

  Scenario: Requête propre — aucun impact
    Given une requête GET "/articles/bonjour-monde?page=2&sort=date"
    When le WAF analyse l'intégrité
    Then aucune contribution "integrity" n'est publiée
    And la latence ajoutée est < 0.5ms

  @deferred
  Scenario: Path traversal refusé en 400
    Given une requête GET "/pages/../../../etc/passwd"
    Then la requête reçoit HTTP 400

  @deferred
  Scenario: Path trop long refusé en 414
    Given une requête GET avec un path de 3000 caractères
    Then la requête reçoit HTTP 414 (URI Too Long)

  @deferred
  Scenario: Content-Type invalide sur POST
    Given une requête POST avec Content-Type: application/json
    And un body qui commence par "<html>" (clairement pas du JSON)
    When le WAF compare Content-Type déclaré et body réel
    Then un log warn est émis avec reason="content_type_mismatch"
    And la requête est transmise (l'app décide de la rejeter)

  @deferred
  Scenario: Path normalisé correctement — accès légitime
    Given une requête GET "/articles//mon-article" (double slash)
    When le WAF normalise le path
    Then le path normalisé est "/articles/mon-article"
