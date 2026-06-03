Feature: Analyse d'Intégrité des Requêtes
  En tant que WAF,
  Je veux détecter les requêtes malformées ou obfusquées
  Afin d'identifier les tentatives d'injection, de path traversal et d'exploitation.

  Background:
    Given le WAF est configuré avec request_integrity.enabled = true
    And request_integrity.max_path_length = 2048
    And request_integrity.max_body_bytes = 10485760  # 10MB

  Scenario: Path traversal — séquence ../
    Given une requête GET "/pages/../../../etc/passwd"
    When le WAF analyse l'intégrité du path
    Then le trust score est décrémenté de 30
    And l'événement est journalisé avec reason="path_traversal_detected"
    And la requête reçoit HTTP 400

  Scenario: Path traversal — encodage URL double
    Given une requête GET "/pages/%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    When le WAF décode et normalise le path
    Then la séquence "../" est détectée après décodage
    And le même traitement qu'un path traversal est appliqué

  Scenario: Null byte dans le path
    Given une requête GET "/page%00.html"
    When le WAF analyse le path
    Then un null byte est détecté
    And le trust score est décrémenté de 30
    And la requête reçoit HTTP 400

  Scenario: Path trop long
    Given une requête GET avec un path de 3000 caractères
    When le WAF vérifie la longueur du path
    Then la requête reçoit HTTP 414 (URI Too Long)
    And l'événement est journalisé avec reason="path_too_long"

  Scenario: Paramètre SQL injection pattern détecté
    Given une requête GET "/search?q=1%20UNION%20SELECT%20%2A%20FROM%20users"
    When le WAF analyse les query params
    Then le pattern SQL "UNION SELECT" est détecté
    And le trust score est décrémenté de 30
    And la requête est loggée avec reason="sqli_pattern_in_params"
    And la requête est QUAND MÊME transmise à l'upstream (la détection contribue au score, ne bloque pas)
    Note: le blocage final dépend du trust score resultant, pas de la détection seule

  Scenario: Paramètre XSS pattern détecté
    Given une requête GET "/page?name=<script>alert(1)</script>"
    When le WAF analyse les query params
    Then le pattern XSS est détecté
    And le trust score est décrémenté de 30

  Scenario: Body trop grand — rejet
    Given une requête POST avec un body de 15MB (> 10MB limit)
    When le WAF vérifie la taille du body
    Then la requête reçoit HTTP 413 (Content Too Large)
    And la connexion upstream n'est pas ouverte

  Scenario: Content-Type invalide sur POST
    Given une requête POST avec Content-Type: application/json
    And un body qui commence par "<html>" (clairement pas du JSON)
    When le WAF compare Content-Type déclaré et body réel
    Then un log warn est émis avec reason="content_type_mismatch"
    And la requête est transmise (l'app décide de la rejeter)

  Scenario: Path normalisé correctement — accès légitime
    Given une requête GET "/articles//mon-article" (double slash)
    When le WAF normalise le path
    Then le path normalisé est "/articles/mon-article"
    And la requête est transmise normalement sans score penalty

  Scenario: Requête propre — aucun impact
    Given une requête GET "/articles/bonjour-monde?page=2&sort=date"
    When le WAF analyse l'intégrité
    Then aucun pattern suspect n'est détecté
    And aucun delta de score n'est appliqué
    And la latence ajoutée est < 0.5ms
