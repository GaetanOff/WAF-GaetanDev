Feature: Reverse Proxy (FR-01)
  En tant que WAF placé devant une ou plusieurs applications,
  Je veux transmettre le trafic légitime vers le bon upstream sans l'altérer
  Afin que la protection soit transparente pour l'application.

  Background:
    Given le WAF est configuré avec upstream.address = "http://10.0.0.1:8080"
    And les protections laissent passer la requête (visiteur légitime)

  Scenario: Requête légitime transmise avec les en-têtes d'origine
    Given un visiteur d'IP "198.51.100.10" envoie GET "/articles?page=2" avec l'en-tête "Accept-Language: fr"
    When le WAF transmet la requête
    Then l'upstream reçoit GET "/articles?page=2"
    And l'en-tête "Accept-Language: fr" est préservé
    And l'upstream reçoit "X-Forwarded-For" et "X-Real-IP" égal à "198.51.100.10"
    And la réponse de l'upstream est renvoyée au visiteur telle quelle

  Scenario: Routage par domaine — première entrée correspondante gagnante
    Given les domaines configurés, dans cet ordre :
      | host             | upstream              |
      | *.a.example      | http://10.0.0.2:80    |
      | api.a.example    | http://10.0.0.3:80    |
      | api.b.example    | http://10.0.0.4:80    |
    When des requêtes arrivent avec les en-têtes Host suivants
    Then elles sont routées ainsi :
      | Host                  | upstream            |
      | api.a.example         | http://10.0.0.2:80  |
      | API.B.example:8443    | http://10.0.0.4:80  |
      | a.example             | http://10.0.0.2:80  |
      | inconnu.example       | http://10.0.0.1:8080|
    # Casse ignorée, port retiré ; un wildcard couvre aussi l'apex ; hôte inconnu
    # → upstream par défaut.

  Scenario: Host réécrit vers l'upstream par défaut
    Given upstream.preserve_host = false
    When une requête arrive avec Host "shop.example"
    Then l'upstream reçoit Host "10.0.0.1:8080"

  Scenario: Host entrant conservé (upstream routant par server_name)
    Given upstream.preserve_host = true
    When une requête arrive avec Host "shop.example"
    Then l'upstream reçoit Host "shop.example"

  Scenario: WebSocket — upgrade HTTP relayé dans les deux sens
    Given l'upstream accepte l'upgrade WebSocket
    When un client envoie une requête "Connection: Upgrade" et "Upgrade: websocket"
    Then le client reçoit "101 Switching Protocols"
    And les octets échangés après l'upgrade transitent dans les deux sens

  Scenario: Upstream indisponible — 502 sans crash
    Given l'upstream ne répond pas (connexion refusée)
    When un visiteur envoie une requête
    Then il reçoit HTTP 502 "bad gateway"
    And le WAF continue de servir les requêtes suivantes (NFR-02)

  Scenario: Préfixe /waf/ réservé — jamais transmis
    When une requête arrive sur "/waf/health", "/waf/metrics" ou "/waf/verify"
    Then le WAF y répond lui-même
    And la requête n'est PAS transmise à l'upstream

  Scenario: En-têtes internes forgés par le client supprimés
    Given un client envoie l'en-tête "X-WAF-Action: PASS"
    When le WAF traite la requête
    Then l'en-tête est supprimé à l'entrée (aucun bypass)
    And l'upstream ne reçoit aucun X-WAF-* fourni par le client
