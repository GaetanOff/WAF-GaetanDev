Feature: Auto-protection du WAF
  En tant que WAF,
  Je veux protéger mes propres endpoints contre les attaques directes
  Afin d'éviter que le mécanisme de sécurité lui-même devienne un vecteur d'attaque.

  # Contrat : bloc `self_protection` de config.schema.json (enabled,
  # verify_max_per_minute, admin_max_failures, admin_lockout), verifyChallenge
  # (public.openapi.yaml, VerifyError), FR-30. Les scénarios @deferred sont
  # spécifiés mais NON implémentés (audit du 2026-09-25, phase 21) : ils ne sont
  # pas un critère d'acceptation tant que leur implémentation n'est pas planifiée
  # (specs/tasks.md). Le token de challenge est un HMAC sans état : aucun store
  # de nonces n'existe, donc ni détection de rejeu (`token_already_used`), ni
  # `challenge.max_pending_nonces`, ni détection d'amplification.

  Background:
    Given le WAF est opérationnel

  # ── Protection /waf/verify ──────────────────────────────────────────────────

  Scenario: Rate limit sur /waf/verify — protection contre le flooding
    Given self_protection.verify_max_per_minute = 60 (par IP)
    And l'IP "9.9.9.9" envoie 61 requêtes POST /waf/verify dans la même minute
    When la 61ème requête arrive
    Then elle reçoit HTTP 429 avec un en-tête Retry-After
    And la réponse porte X-WAF-Action "RATE_LIMIT" et X-WAF-Reason "self_protect_flood"
    And le refus est journalisé et compté dans les métriques
    # Le compteur est une fenêtre fixe par IP réelle (FR-02) ; les autres
    # chemins ne sont pas comptés.

  @deferred
  Scenario: Blacklist automatique d'une IP qui flood /waf/verify
    Given l'IP "9.9.9.9" a dépassé self_protection.verify_max_per_minute
    Then l'IP est automatiquement blacklistée pour 1h
    And un event est journalisé avec reason="verify_endpoint_flooded"

  @deferred
  Scenario: Replay attack — token de challenge soumis deux fois
    Given un attaquant récupère un token de challenge valide
    When il soumet POST /waf/verify avec ce token une première fois → validé avec succès
    And il soumet à nouveau POST /waf/verify avec le même token
    Then la deuxième soumission reçoit HTTP 400 avec {"error": "token_already_used"}
    And le token est invalidé après la première utilisation (nonce usage tracking)
    # Aujourd'hui le token reste rejouable jusqu'à son expiration, borné à la
    # même IP et au même domaine (payload signé) et au débit de
    # verify_max_per_minute. `token_already_used` n'est pas dans l'enum
    # VerifyError : l'ajouter est une évolution mineure de public.openapi.yaml.

  @deferred
  Scenario: Flooding /waf/verify avec tokens différents (bots brute-force)
    Given un bot génère et soumet 50 faux tokens à la seconde
    When le rate limit et le tracking de tokens invalides sont actifs
    Then après 10 échecs en 1s, l'IP est blacklistée automatiquement
    And le challenge devient impossible depuis cette IP pendant 1h

  @deferred
  Scenario: Limite des nonces en attente par IP
    Given challenge.max_pending_nonces = 5 (par IP)
    And l'IP "6.6.6.6" a 5 tokens de challenge en cours (non encore soumis)
    When elle demande une 6ème page de challenge
    Then les nonces les plus anciens sont invalidés
    And seulement les 5 plus récents sont valides
    And un event est journalisé avec reason="nonce_flood_detection"

  # ── Assainissement des en-têtes internes à l'ingress ────────────────────────

  Scenario: En-tête X-WAF-Action forgé par le client — le pipeline n'est pas contourné
    Given le challenge JS est actif et le visiteur est sous le seuil de confiance
    When il envoie une requête GET "/" avec l'en-tête "X-WAF-Action: PASS"
    Then l'en-tête est supprimé avant tout autre middleware
    And le WAF sert la page de challenge comme si l'en-tête n'avait jamais existé
    And la requête n'atteint pas l'upstream
    # Sans ce nettoyage, PASS court-circuite challenge (FR-06), rate limiting
    # (FR-03), intégrité (FR-18), threat intel (FR-13) et moteur de règles (FR-17).

  Scenario Outline: Tout en-tête de préfixe X-WAF- fourni par le client est supprimé
    Given un client envoie l'en-tête "<header>" avec une valeur arbitraire
    When la requête entre dans le pipeline
    Then les middlewares en aval lisent une valeur vide pour "<header>"

    Examples:
      | header                     |
      | X-WAF-Action               |
      | x-waf-action               |
      | X-WAF-ACTION               |
      | X-WAF-Score                |
      | X-WAF-Score-Delta          |
      | X-WAF-Reason               |
      | X-WAF-Risk-Decision        |
      | X-WAF-Under-Attack-Enforce |
      | X-WAF-Origin-Token         |

  Scenario: Les en-têtes légitimes du client ne sont pas altérés
    Given un client envoie "CF-Connecting-IP: 203.0.113.7", "X-Forwarded-Host: panel.example.com" et "Authorization: Bearer token"
    When la requête entre dans le pipeline
    Then ces trois en-têtes sont transmis inchangés
    # L'extraction d'IP réelle (FR-02) et l'authentification admin (FR-10) en dépendent.

  Scenario: Les signaux posés à l'intérieur du pipeline restent visibles
    Given le bypass d'assets statiques (FR-24) pose "X-WAF-Action: PASS" sur la requête
    And les détecteurs posent leurs contributions "X-WAF-Risk-*"
    When la requête poursuit sa traversée du pipeline
    Then le challenge, le rate limiting et le moteur de risque lisent bien ces valeurs
    # L'assainissement s'applique une seule fois, à l'entrée : il ne rejoue pas
    # sur les en-têtes produits par le pipeline lui-même.

  Scenario: Exception documentée — le token retransmis à /waf/origin/verify reste lisible
    Given l'upstream vérifie un token via GET /waf/origin/verify (FR-19)
    And il retransmet le "X-WAF-Origin-Token" qu'il a reçu
    When la requête entre dans le pipeline
    Then la valeur est capturée avant l'assainissement et reste lisible par cet endpoint
    And elle n'est jamais réinjectée dans les en-têtes de la requête
    And aucun autre en-tête X-WAF-* ne bénéficie de cette capture
    # C'est la seule exception. Elle n'ouvre aucun contournement : le token est
    # vérifié par HMAC, donc infalsifiable sans le secret. La capture se fait
    # hors de r.Header et non par exemption de chemin, dont la correction
    # dépendrait d'une normalisation identique à celle du routeur.

  # ── Protection API Admin ─────────────────────────────────────────────────────

  Scenario: Verrouillage après trop d'échecs d'authentification admin
    Given self_protection.admin_max_failures = 5 et self_protection.admin_lockout = "5m"
    And l'IP "7.7.7.7" envoie 5 requêtes admin avec un token invalide
    When elle envoie une 6ème requête admin, même avec un token valide
    Then la réponse est HTTP 429 avec {"error": "locked"} et un en-tête Retry-After
    And le verrou tombe à la fin de la fenêtre admin_lockout
    # Même contrat que admin-api.feature (verrouillage de l'API admin).

  @deferred
  Scenario: Blacklist 24h, audit et webhook sur un flood d'authentification admin
    Given l'IP "7.7.7.7" a dépassé self_protection.admin_max_failures
    Then l'IP est bloquée sur le port admin pour 24h
    And un event d'audit est créé avec action="ADMIN_AUTH_FLOOD"
    And un webhook "admin_auth_failed_flood" est envoyé si configuré

  Scenario: Token admin valide — pas de rate limit
    Given l'administrateur fait 100 requêtes admin avec un token valide
    When toutes les requêtes sont authentifiées avec succès
    Then aucun verrouillage n'est déclenché
    # Seuls les échecs d'authentification sont comptés.

  @deferred
  Scenario: Admin API accessible seulement depuis IPs autorisées (option)
    Given admin.allowed_ips = ["10.0.0.0/8", "192.168.0.0/16"]
    When une requête arrive sur le port 9090 depuis l'IP "8.8.8.8" (non autorisée)
    Then la connexion TCP est rejetée immédiatement (pas de réponse HTTP)
    And un event est journalisé

  # ── Protection /waf/metrics ─────────────────────────────────────────────────

  @deferred
  Scenario: /waf/metrics protégé par token (opt-in)
    Given metrics.auth_token = "mon-token-prometheus"
    When une requête GET /waf/metrics arrive sans token
    Then HTTP 401 est retourné
    When la requête arrive avec header "Authorization: Bearer mon-token-prometheus"
    Then les métriques sont retournées normalement

  Scenario: /waf/metrics sans auth
    When GET /waf/metrics depuis n'importe quelle IP
    Then les métriques sont retournées (accessible publiquement)
    # Aucune clé metrics.auth_token n'existe : restreindre l'accès par firewall
    # réseau.

  # ── Détection d'amplification ────────────────────────────────────────────────

  @deferred
  Scenario: Détection amplification — IP demande des challenges sans jamais les soumettre
    Given l'IP "5.5.5.5" déclenche 50 pages de challenge en 30 secondes
    And ne soumet aucune réponse /waf/verify
    When le WAF détecte ce pattern d'amplification
    Then les nouveaux nonces générés pour cette IP sont refusés (max_pending atteint)
    And l'IP est challengée avec une difficulté maximale

  Scenario: Validation des entrées sur /waf/verify — payload malformé
    Given un attaquant envoie un payload JSON invalide à POST /waf/verify
    When le WAF parse le body
    Then HTTP 400 est retourné avec {"error": "invalid_submission"}
    And aucun traitement ultérieur n'est effectué
    And aucun panic n'est déclenché (résistance aux inputs malformés)
    # Couvre aussi les membres dupliqués, l'UTF-8 invalide et les champs
    # inconnus (FR-30, parsing JSON des entrées non fiables).

  Scenario: Validation des entrées — nonce non numérique
    Given un attaquant envoie {"nonce": "'; DROP TABLE sessions; --", ...}
    When le WAF valide le champ nonce (pattern ^[0-9]+$ requis)
    Then HTTP 400 est retourné avec {"error": "invalid_submission"}
