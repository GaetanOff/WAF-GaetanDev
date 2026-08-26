Feature: Protection Slowloris & Slow HTTP
  En tant que WAF,
  Je veux détecter et bloquer les attaques Slowloris et Slow POST
  Afin d'éviter l'épuisement du pool de connexions par des requêtes intentionnellement lentes.

  Background:
    Given le WAF est configuré avec:
      | slow_attacks.headers_timeout  | 10s           |
      | slow_attacks.body_min_rate    | 100           | (bytes/seconde)
      | slow_attacks.max_conns_per_ip | 50            |
      | slow_attacks.idle_read_timeout| 30s           |

  # ── Slowloris (slow headers) ────────────────────────────────────────────────

  Scenario: Slowloris — headers jamais terminés dans le délai
    Given un attaquant ouvre une connexion TCP et envoie "GET / HTTP/1.1\r\nHost: example.com\r\n"
    When 11 secondes s'écoulent sans que les headers soient terminés (pas de \r\n\r\n final)
    Then le WAF ferme la connexion
    And retourne HTTP 408 Request Timeout
    And un event sécurité est journalisé avec reason="slowloris_headers_timeout"

  Scenario: Slowloris classique — headers envoyés un par un toutes les 9s
    Given un attaquant envoie un header par ligne toutes les 9 secondes ("X-a: b\r\n", "X-c: d\r\n"...)
    And chaque ligne individuelle est envoyée sous 10s
    But les headers ne sont jamais terminés avec \r\n\r\n
    When le timer global de headers_timeout (10s) est dépassé depuis le premier byte
    Then la connexion est fermée avec HTTP 408

  Scenario: Requête légitime — headers reçus rapidement
    Given un navigateur envoie ses headers complets en 200ms
    When les headers arrivent bien avant le timeout de 10s
    Then la connexion n'est pas fermée
    And la requête est traitée normalement

  Scenario: Timeout headers ne bloque pas les connexions légitimes
    Given 100 visiteurs légitimes envoient leurs headers en < 1s
    When ils coexistent avec 5 attaquants Slowloris
    Then les 100 visiteurs légitimes sont traités normalement
    And les 5 attaquants voient leurs connexions fermées après 10s

  # ── Slow POST (slow body) ────────────────────────────────────────────────────

  Scenario: Slow POST — body envoyé trop lentement
    Given une requête POST avec Content-Length: 1000000 (1MB)
    When le body arrive à 50 bytes/seconde (en dessous du seuil 100 B/s)
    Then le WAF ferme la connexion après détection du sous-débit
    And retourne HTTP 408
    And un event est journalisé avec reason="slow_body_rate"

  Scenario: Slow POST légitime — connexion lente mais acceptable
    Given un client avec une mauvaise connexion (100 bytes/seconde exactement)
    When le body arrive à exactement le seuil minimal
    Then la connexion n'est pas fermée (seuil non dépassé)

  # ── Limite de connexions par IP ─────────────────────────────────────────────

  Scenario: Trop de connexions simultanées depuis une IP
    Given max_conns_per_ip = 50
    And l'IP "1.2.3.4" a déjà 50 connexions actives
    When elle ouvre une 51ème connexion
    Then le WAF rejette la connexion (TCP RST ou HTTP 429 selon config)
    And un event est journalisé avec reason="too_many_connections_per_ip"

  Scenario: Requête unique portant des milliers de lignes d'en-tête
    # max_conns_per_ip borne le nombre de requêtes concurrentes ; il ne borne pas
    # le coût de parsing d'UNE requête. C'est le rôle de max_header_value_count.
    Given max_header_value_count = 100
    When une IP envoie une seule requête portant 5 000 lignes d'en-tête distinctes
    Then le serveur HTTP rejette la requête avant d'exécuter le moindre middleware
    And la mémoire consommée par le parsing des en-têtes reste bornée

  Scenario: Requête légitime sous la limite d'en-têtes
    Given max_header_value_count = 100
    When un navigateur envoie une requête portant ~25 lignes d'en-tête
    Then la requête est traitée normalement

  Scenario: En-tête unique à valeurs multiples séparées par des virgules
    # Une ligne "Accept: a, b, c" compte pour 1, pas 3 : la limite vise la
    # répétition de lignes, pas la richesse d'une valeur.
    Given max_header_value_count = 100
    When un client envoie une requête dont un en-tête porte 300 valeurs séparées par des virgules sur une seule ligne
    Then la requête n'est pas rejetée pour dépassement de max_header_value_count

  Scenario: IPs whitelistées exemptées de la limite
    Given l'IP "10.0.0.1" est dans la whitelist
    When elle ouvre 200 connexions simultanées
    Then aucune connexion n'est rejetée pour cause de limite

  Scenario: Connexion idle sans données — fermeture
    Given une connexion TCP est établie
    And idle_read_timeout = 30s
    When aucun byte n'est reçu pendant 31 secondes
    Then la connexion est fermée proprement
    And aucun log d'erreur sécurité n'est émis (comportement normal pour connexion morte)

  # ── Métriques Slowloris ─────────────────────────────────────────────────────

  Scenario: Métriques de protection Slowloris exposées
    When GET /waf/metrics
    Then les métriques contiennent:
      | waf_slowloris_blocked_total | connexions Slowloris fermées |
      | waf_slow_post_blocked_total | Slow POST fermés             |
      | waf_connections_per_ip_max  | max connexions vues par IP   |
      | waf_active_connections      | connexions actives total      |

  Scenario: Détection sous attaque Slowloris massivement distribuée
    Given 10 000 IPs distinctes ouvrent chacune 1 connexion Slowloris
    When chaque connexion dépasse headers_timeout
    Then le WAF ferme chaque connexion à son expiration
    And la mémoire utilisée par les connexions pendantes est bornée
    And les visiteurs légitimes continuent à être servis
