Feature: TLS / JA3 Fingerprinting
  En tant que WAF,
  Je veux utiliser le fingerprint TLS du client pour une détection de bot plus robuste
  Afin d'identifier les outils d'attaque même quand ils imitent un navigateur légitime.

  Background:
    Given le WAF est configuré avec tls_fingerprint.enabled = true

  Scenario: Mode Cloudflare — JA3 lu depuis le header CF
    Given le WAF est derrière Cloudflare avec Bot Management activé
    And Cloudflare envoie le header "Cf-Bot-Management-Ja3Hash: 3b5074b1b5d032e5620f69f9159a1b97"
    When le WAF traite la requête
    Then le JA3 hash "3b5074b1b5d032e5620f69f9159a1b97" est extrait
    And stocké dans le VisitorProfile

  Scenario: JA3 hash en blacklist — score décrémenté
    Given le hash "3b5074b1b5d032e5620f69f9159a1b97" est dans la blacklist JA3 (Mirai)
    When une requête avec ce JA3 arrive
    Then le trust score est décrémenté de 40
    And l'événement est journalisé avec reason="ja3_blacklisted" ja3="3b5074b1b5d032e5620f69f9159a1b97"
    And le visiteur reçoit le challenge immédiatement

  Scenario: JA3 propre — aucun impact
    Given le hash JA3 "a0e9f5d64349fb13191bc781f81f42e1" n'est pas en blacklist
    When une requête avec ce JA3 arrive
    Then aucun delta de score n'est appliqué pour le JA3

  Scenario: Mode TLS direct — JA3 calculé depuis le ClientHello
    Given le WAF termine lui-même le TLS (server.tls configuré)
    And un client se connecte avec TLS 1.3, cipher suites [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384]
    When le WAF capture le ClientHello via GetConfigForClient
    Then le JA3 hash est calculé correctement
    And injecté dans le contexte HTTP de la requête

  Scenario: Cohérence JA3 entre sessions — swap détecté
    Given un visiteur avec cookie valide a un JA3 "a0e9f5d6" enregistré
    When il revient avec un JA3 "ff00aa11" (outil différent)
    Then le WAF détecte l'incohérence de fingerprint TLS
    And le trust score est décrémenté de 15
    And l'événement est journalisé avec reason="ja3_session_mismatch"

  Scenario: JA3 de Python requests — score dégradé
    Given le hash JA3 "ab16e0fd5f7a6bb6a0a2da7d8e9e3a78" correspond à python-requests
    And ce hash est en blacklist avec contexte configurable (selon déploiement)
    When une requête avec ce JA3 arrive
    Then le comportement dépend de la configuration ja3_blacklist

  Scenario: CF-Bot-Management-Ja3Hash forgé depuis une IP non-Cloudflare
    Given la source de la requête est l'IP "8.8.8.8" (non Cloudflare)
    And la requête contient le header "Cf-Bot-Management-Ja3Hash: xxx"
    When le middleware Cloudflare traite la requête
    Then le header JA3 est ignoré (la source n'est pas Cloudflare)
    And aucun score JA3 n'est appliqué

  Scenario: JA3 non disponible — feature désactivée gracieusement
    Given le WAF est derrière Cloudflare sans Bot Management
    And aucun header JA3 n'est présent
    And le WAF ne termine pas le TLS lui-même
    When une requête arrive
    Then le WAF fonctionne normalement sans JA3
    And aucune erreur n'est loggée

  Scenario: Ajout d'un hash JA3 à la blacklist via API
    Given l'API admin est authentifiée
    When POST /waf/admin/ja3-blacklist avec body {"hash": "deadbeef12345678", "reason": "known C2 tool"}
    Then le hash est immédiatement actif en blacklist
    Et les nouvelles requêtes avec ce JA3 sont challengées
