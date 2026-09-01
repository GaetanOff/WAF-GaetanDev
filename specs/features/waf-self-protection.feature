Feature: Auto-protection du WAF
  En tant que WAF,
  Je veux protéger mes propres endpoints contre les attaques directes
  Afin d'éviter que le mécanisme de sécurité lui-même devienne un vecteur d'attaque.

  Background:
    Given le WAF est opérationnel

  # ── Protection /waf/verify ──────────────────────────────────────────────────

  Scenario: Rate limit sur /waf/verify — protection contre le flooding
    Given self_protection.verify_rate_limit = 10 (req/s par IP)
    And l'IP "9.9.9.9" envoie 20 requêtes POST /waf/verify en 1 seconde
    When le rate limit est déclenché à la 11ème requête
    Then les requêtes suivantes reçoivent HTTP 429
    And l'IP est automatiquement blacklistée pour 1h
    And un event est journalisé avec reason="verify_endpoint_flooded"

  Scenario: Replay attack — token de challenge soumis deux fois
    Given un attaquant récupère un token de challenge valide
    When il soumet POST /waf/verify avec ce token une première fois → validé avec succès
    And il soumet à nouveau POST /waf/verify avec le même token
    Then la deuxième soumission reçoit HTTP 400 avec {"error": "token_already_used"}
    And le token est invalidé après la première utilisation (nonce usage tracking)

  Scenario: Flooding /waf/verify avec tokens différents (bots brute-force)
    Given un bot génère et soumet 50 faux tokens à la seconde
    When le rate limit et le tracking de tokens invalides sont actifs
    Then après 10 échecs en 1s, l'IP est blacklistée automatiquement
    And le challenge devient impossible depuis cette IP pendant 1h

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

  # ── Protection API Admin ─────────────────────────────────────────────────────

  Scenario: Rate limit sur les tentatives d'authentification admin
    Given self_protection.admin_auth_rate = 5 (échecs/min par IP)
    And l'IP "7.7.7.7" envoie 6 requêtes admin avec un token invalide en 1 minute
    When le 6ème échec est enregistré
    Then l'IP est bloquée sur le port admin pour 24h
    And un event d'audit est créé avec action="ADMIN_AUTH_FLOOD"
    And un webhook "admin_auth_failed_flood" est envoyé si configuré

  Scenario: Token admin valide — pas de rate limit
    Given l'administrateur fait 100 requêtes admin avec un token valide
    When toutes les requêtes sont authentifiées avec succès
    Then aucun rate limit n'est déclenché

  Scenario: Admin API accessible seulement depuis IPs autorisées (option)
    Given admin.allowed_ips = ["10.0.0.0/8", "192.168.0.0/16"]
    When une requête arrive sur le port 9090 depuis l'IP "8.8.8.8" (non autorisée)
    Then la connexion TCP est rejetée immédiatement (pas de réponse HTTP)
    And un event est journalisé

  # ── Protection /waf/metrics ─────────────────────────────────────────────────

  Scenario: /waf/metrics protégé par token (opt-in)
    Given metrics.auth_token = "mon-token-prometheus"
    When une requête GET /waf/metrics arrive sans token
    Then HTTP 401 est retourné
    When la requête arrive avec header "Authorization: Bearer mon-token-prometheus"
    Then les métriques sont retournées normalement

  Scenario: /waf/metrics sans auth (défaut pour Prometheus scraping facile)
    Given metrics.auth_token = "" (non configuré)
    When GET /waf/metrics depuis n'importe quelle IP
    Then les métriques sont retournées (accessible publiquement)
    Note: Il est recommandé de restreindre via firewall réseau

  # ── Détection d'amplification ────────────────────────────────────────────────

  Scenario: Détection amplification — IP demande des challenges sans jamais les soumettre
    Given l'IP "5.5.5.5" déclenche 50 pages de challenge en 30 secondes
    And ne soumet aucune réponse /waf/verify
    When le WAF détecte ce pattern d'amplification
    Then les nouveaux nonces générés pour cette IP sont refusés (max_pending atteint)
    And l'IP est challengée avec une difficulté maximale

  Scenario: Validation des entrées sur /waf/verify — payload malformé
    Given un attaquant envoie un payload JSON invalide à POST /waf/verify
    When le WAF parse le body
    Then HTTP 400 est retourné avec {"error": "invalid_json"}
    And aucun traitement ultérieur n'est effectué
    And aucun panic n'est déclenché (résistance aux inputs malformés)

  Scenario: Validation des entrées — nonce non numérique
    Given un attaquant envoie {"nonce": "'; DROP TABLE sessions; --", ...}
    When le WAF valide le champ nonce (pattern ^[0-9]+$ requis)
    Then HTTP 400 est retourné avec {"error": "invalid_nonce_format"}
