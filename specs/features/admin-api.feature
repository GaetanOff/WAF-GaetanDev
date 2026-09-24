Feature: API d'administration (FR-10)
  En tant qu'opérateur du WAF,
  Je veux piloter le WAF par une API REST protégée sur un port privé
  Afin de gérer les listes d'accès, les visiteurs et la configuration sans redémarrage.

  Contrat : specs/api/admin.openapi.yaml. Servie sur server.admin_listen (défaut
  127.0.0.1:9090), jamais sur le listener public.

  Background:
    Given l'API admin est activée avec un token Bearer de 32 caractères au moins
    And self_protection.admin_max_failures = 5 et self_protection.admin_lockout = "5m"

  # --- Authentification ---

  Scenario: Requête sans token — refusée
    When GET /waf/stats sans en-tête Authorization
    Then la réponse est HTTP 401 avec {"error": "unauthorized"}

  Scenario: Token invalide — refusé
    When GET /waf/stats avec "Authorization: Bearer mauvais-token"
    Then la réponse est HTTP 401
    # La comparaison est en temps constant.

  Scenario: Token valide — accès accordé
    When GET /waf/stats avec le bon token Bearer
    Then la réponse est HTTP 200

  Scenario: Brute-force — IP verrouillée après trop d'échecs
    Given une IP a envoyé 5 tokens invalides
    When elle envoie une nouvelle requête, même avec le bon token
    Then la réponse est HTTP 429 avec {"error": "locked"}
    And l'en-tête "Retry-After" est présent

  Scenario: Health check non authentifié
    When GET /waf/health sans token
    Then la réponse est HTTP 200 avec status et version

  # --- CRUD whitelist / blacklist ---

  Scenario: Ajout en blacklist — effet immédiat
    When POST /waf/admin/blacklist avec {"ip": "5.5.5.5"}
    Then la réponse est HTTP 201 avec l'entrée normalisée et added_at
    And l'IP est bloquée immédiatement par le listener public
    And l'action est journalisée dans l'audit (add_blacklist)

  Scenario: Doublon — conflit
    Given "5.5.5.5" est déjà en blacklist
    When POST /waf/admin/blacklist avec {"ip": "5.5.5.5"}
    Then la réponse est HTTP 409 avec {"error": "already_exists"}

  Scenario: IP ou CIDR invalide — rejetée
    When POST /waf/admin/whitelist avec {"ip": "not-an-ip"}
    Then la réponse est HTTP 400 avec {"error": "invalid_ip"}

  Scenario: Champ inconnu — rejeté
    When POST /waf/admin/whitelist avec {"ip": "1.2.3.4", "extra": true}
    Then la réponse est HTTP 400

  Scenario: Suppression d'un CIDR encodé dans l'URL
    Given "192.168.0.0/24" est en whitelist
    When DELETE /waf/admin/whitelist/192.168.0.0%2F24
    Then la réponse est HTTP 204
    And l'entrée n'est plus appliquée

  Scenario: Suppression d'une entrée absente
    When DELETE /waf/admin/blacklist/9.9.9.9
    Then la réponse est HTTP 404

  # --- Visiteurs et pagination ---

  Scenario: Pagination des listes
    Given 5 visiteurs sont suivis
    When GET /waf/admin/visitors?page=2&limit=2
    Then la réponse contient 2 éléments et total = 5
    When GET /waf/admin/visitors?page=4&limit=2
    Then la réponse contient 0 élément et total = 5

  Scenario: Pagination — bornes
    When GET /waf/admin/visitors?limit=5000
    Then au plus 1000 éléments sont retournés
    When GET /waf/admin/visitors?page=0&limit=-1
    Then les valeurs par défaut s'appliquent (page = 1, limit = 50)

  Scenario: Filtre et tri des visiteurs
    When GET /waf/admin/visitors?state=CHALLENGED&sort=score_asc
    Then seuls les visiteurs CHALLENGED sont retournés, du score le plus bas au plus haut

  Scenario: Réinitialisation d'un visiteur
    When DELETE /waf/admin/visitors/{ip_hash} d'un visiteur suivi
    Then la réponse est HTTP 204 et le visiteur n'est plus suivi
    And l'action est journalisée dans l'audit (reset_visitor)

  # --- Configuration, événements, statistiques ---

  Scenario: Configuration consultée — secrets masqués
    When GET /waf/admin/config
    Then challenge.secret_key, admin.token et storage.redis.password valent "***"
    And origin_protection.secret, threat_intel.abuseipdb.api_key et alerting.webhooks[].url valent "***"
    And la configuration active garde ses secrets (seule la réponse est masquée)

  Scenario: Modification à chaud de la configuration
    When PATCH /waf/admin/config avec {"rate_limit": {"burst": 40}}
    Then la réponse est HTTP 200 avec updated_fields = ["rate_limit.burst"]
    And le rate limiter applique le nouveau burst sans redémarrage

  Scenario: Modification invalide — rien n'est appliqué
    When PATCH /waf/admin/config avec {"trust": {"block_threshold": 90}}
    Then la réponse est HTTP 400
    And la configuration en vigueur est inchangée

  Scenario: Événements récents et statistiques
    Given le WAF a bloqué une requête et en a laissé passer deux
    When GET /waf/admin/events
    Then l'événement BLOCK est listé (les PASS ne sont pas retenus)
    When GET /waf/stats
    Then total_requests = 3, requests_passed = 2 et requests_blocked = 1
