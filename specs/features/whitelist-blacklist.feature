Feature: Gestion Whitelist / Blacklist
  En tant qu'administrateur du WAF,
  Je veux gérer des listes d'IPs autorisées et bloquées
  Afin de contrôler finement l'accès au site.

  Background:
    Given le WAF est opérationnel
    And la whitelist contient "192.168.1.0/24"
    And la blacklist contient "10.0.0.5"

  Scenario: IP en whitelist — pass-through total
    Given une requête provenant de "192.168.1.100" (dans 192.168.1.0/24)
    When le WAF traite la requête
    Then la requête est immédiatement transmise à l'upstream
    And aucun middleware de sécurité n'est appliqué (rate limit, challenge, score)
    And le log indique action="PASS" reason="whitelist_cidr"

  Scenario: IP exacte en whitelist
    Given l'IP "203.0.113.42" est ajoutée en whitelist
    When une requête provient de cette IP
    Then la requête est transmise sans aucune vérification

  Scenario: IP en blacklist — blocage immédiat
    Given une requête provenant de "10.0.0.5" (dans la blacklist)
    When le WAF traite la requête
    Then la requête reçoit HTTP 403
    And le log indique action="BLOCK" reason="blacklist_exact"
    And aucune requête n'est envoyée à l'upstream

  Scenario: CIDR en blacklist — blocage de la plage
    Given le CIDR "198.51.100.0/24" est ajouté en blacklist
    When une requête provient de "198.51.100.150"
    Then la requête reçoit HTTP 403

  Scenario: IP dans whitelist ET blacklist — whitelist prioritaire
    Given "172.16.0.1" est dans la whitelist
    And "172.16.0.1" est dans la blacklist
    When une requête provient de "172.16.0.1"
    Then la requête est transmise (whitelist a la priorité sur blacklist)

  Scenario: Hot-reload de la blacklist sans redémarrage
    Given le WAF est en cours d'exécution
    When l'administrateur ajoute "7.7.7.7" à la blacklist (via API ou reload config)
    Then dans les 5 secondes, les nouvelles requêtes de "7.7.7.7" reçoivent 403
    And les connexions existantes ne sont pas interrompues

  Scenario: User-Agent de bot légitime whitelisté
    Given le pattern "Googlebot" est dans la whitelist_user_agents
    When une requête arrive avec User-Agent "Mozilla/5.0 (compatible; Googlebot/2.1)"
    Then la requête est transmise sans challenge
    And aucun score n'est calculé

  Scenario: API admin — ajout en blacklist
    Given l'API admin est authentifiée avec un token valide
    When POST /waf/admin/blacklist avec body {"ip": "1.2.3.4"}
    Then la réponse est HTTP 201
    And l'IP "1.2.3.4" est immédiatement active en blacklist

  Scenario: API admin — suppression de la blacklist
    Given "10.0.0.5" est en blacklist
    When DELETE /waf/admin/blacklist/10.0.0.5 avec token valide
    Then la réponse est HTTP 204
    And les futures requêtes de "10.0.0.5" ne sont plus bloquées

  Scenario: API admin — token invalide
    When DELETE /waf/admin/blacklist/10.0.0.5 sans token d'authentification
    Then la réponse est HTTP 401

  Scenario: Persistance des listes après redémarrage
    Given "8.8.4.4" a été ajouté en blacklist via l'API admin
    When le WAF est redémarré
    Then "8.8.4.4" est toujours en blacklist (si sauvegarde config activée)
