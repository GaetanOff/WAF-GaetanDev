Feature: Protection Slowloris & Slow HTTP
  En tant que WAF,
  Je veux borner les requêtes lentes et concurrentes d'un même client
  Afin d'éviter l'épuisement du pool de connexions par des requêtes intentionnellement lentes.

  # Contrat : bloc slowloris et clés server.read_timeout, server.idle_timeout,
  # server.max_header_bytes, server.max_header_value_count de config.schema.json
  # (FR-23, NFR-11). Les délais sont ceux du http.Server de Go : une échéance
  # dépassée ferme la connexion, sans réponse HTTP.
  # Les scénarios @deferred sont spécifiés mais NON implémentés (audit du
  # 2026-10-01) : ils ne sont pas un critère d'acceptation.

  Background:
    Given le WAF est configuré avec:
      | slowloris.enabled                | true |
      | slowloris.max_connections_per_ip | 50   |
      | slowloris.header_timeout         | 10s  |
      | server.read_timeout              | 30s  |
      | server.idle_timeout              | 60s  |

  # ── Slowloris (slow headers) ────────────────────────────────────────────────

  Scenario: Slowloris — en-têtes jamais terminés dans le délai
    Given un attaquant ouvre une connexion TCP et envoie "GET / HTTP/1.1\r\nHost: example.com\r\n"
    When 11 secondes s'écoulent sans que les en-têtes soient terminés (pas de \r\n\r\n final)
    Then le serveur HTTP ferme la connexion sans envoyer de réponse
    And aucun middleware n'est exécuté, donc aucun event de sécurité n'est journalisé

  Scenario: Slowloris classique — en-têtes envoyés un par un toutes les 9 s
    Given un attaquant envoie une ligne d'en-tête toutes les 9 secondes ("X-a: b\r\n", "X-c: d\r\n"...)
    But les en-têtes ne sont jamais terminés par \r\n\r\n
    When header_timeout (10 s) est dépassé depuis le début de la lecture de la requête
    Then la connexion est fermée sans réponse
    # Le délai porte sur la lecture complète des en-têtes, pas sur chaque ligne.

  Scenario: header_timeout s'applique même slowloris désactivé
    Given slowloris.enabled = false
    When un client n'a pas terminé ses en-têtes après 10 secondes
    Then la connexion est fermée sans réponse
    # Le délai par défaut de 10 s reste appliqué ; seule la borne par IP disparaît.

  Scenario: Requête légitime — en-têtes reçus rapidement
    Given un navigateur envoie ses en-têtes complets en 200 ms
    When les en-têtes arrivent bien avant le délai de 10 s
    Then la connexion n'est pas fermée
    And la requête est traitée normalement

  @deferred
  Scenario: Réponse 408 et event slowloris_headers_timeout à l'expiration des en-têtes
    When un client dépasse header_timeout
    Then le WAF répond HTTP 408 Request Timeout avant de fermer la connexion
    And un event sécurité est journalisé avec reason="slowloris_headers_timeout"

  # ── Slow POST (slow body) ────────────────────────────────────────────────────

  Scenario: Slow POST — requête plus longue que read_timeout
    Given une requête POST avec Content-Length: 1000000 (1 Mo)
    When le corps arrive si lentement que la lecture de la requête dépasse server.read_timeout (30 s)
    Then la lecture du corps échoue et la connexion est fermée
    # read_timeout borne la durée totale de lecture (en-têtes + corps), pas un débit.

  @deferred
  Scenario: Slow POST — débit minimal du corps
    Given slow_attacks.body_min_rate = 100 (octets/seconde)
    When le corps arrive à 50 octets/seconde
    Then le WAF ferme la connexion après détection du sous-débit
    And retourne HTTP 408
    And un event est journalisé avec reason="slow_body_rate"

  # ── Limite de requêtes concurrentes par IP ──────────────────────────────────

  Scenario: Trop de requêtes simultanées depuis une IP
    # Derrière Cloudflare, les connexions TCP viennent des points de présence :
    # la borne compte les requêtes en cours par IP réelle du visiteur (FR-02),
    # une IPv6 par son /64, pas les connexions TCP.
    Given max_connections_per_ip = 50
    And l'IP "1.2.3.4" a déjà 50 requêtes en cours de traitement
    When elle envoie une 51ème requête
    Then le WAF répond HTTP 429 avec "Retry-After: 10"
    And la réponse porte "X-WAF-Action: RATE_LIMIT" et "X-WAF-Reason: too_many_connections_per_ip"
    And un event est journalisé avec action="RATE_LIMIT" reason="too_many_connections_per_ip"
    And la requête est comptée dans waf_requests_total{action="RATE_LIMIT"}

  Scenario: La borne est libérée à la fin de chaque requête
    Given max_connections_per_ip = 1
    When l'IP "1.2.3.4" envoie deux requêtes successives, la seconde après la fin de la première
    Then les deux requêtes sont traitées normalement

  Scenario: /waf/health est exempté de la borne par IP
    Given l'IP "1.2.3.4" a atteint max_connections_per_ip
    When elle envoie GET /waf/health
    Then la sonde répond 200

  Scenario: Requête unique portant des milliers de lignes d'en-tête
    # max_connections_per_ip borne le nombre de requêtes concurrentes ; il ne borne pas
    # le coût de parsing d'UNE requête. C'est le rôle de max_header_value_count.
    Given max_header_value_count = 100
    When une IP envoie une seule requête portant 5 000 lignes d'en-tête distinctes
    Then le serveur HTTP rejette la requête avant d'exécuter le moindre middleware
    And la mémoire consommée par le parsing des en-têtes reste bornée

  Scenario: En-têtes trop volumineux — refusés au parsing
    Given server.max_header_bytes = 65536 (défaut)
    When un client envoie une requête dont les en-têtes pèsent 200 Kio
    Then le serveur HTTP répond 431 avant d'exécuter le moindre middleware

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

  @deferred
  Scenario: IPs whitelistées exemptées de la limite
    # La borne est appliquée dans l'enveloppe, avant la whitelist : une IP
    # whitelistée y est soumise comme les autres.
    Given l'IP "10.0.0.1" est dans la whitelist
    When elle envoie 200 requêtes simultanées
    Then aucune requête n'est rejetée pour cause de limite

  @deferred
  Scenario: Rejet TCP (RST) au lieu du 429
    Given un mode de rejet "tcp_reset" configuré
    When une IP dépasse max_connections_per_ip
    Then la connexion est réinitialisée sans réponse HTTP

  # ── Connexions inactives ────────────────────────────────────────────────────

  Scenario: Connexion keep-alive inactive — fermeture
    Given une connexion keep-alive a servi une requête
    And server.idle_timeout = 60s
    When aucun octet n'est reçu pendant 61 secondes
    Then la connexion est fermée proprement
    And aucun log d'erreur sécurité n'est émis (comportement normal pour connexion morte)

  # ── Métriques Slowloris ─────────────────────────────────────────────────────

  Scenario: Refus de la borne par IP visibles dans les métriques
    Given une IP a reçu un 429 too_many_connections_per_ip
    When GET /waf/metrics
    Then waf_requests_total{action="RATE_LIMIT"} compte ce refus

  @deferred
  Scenario: Métriques dédiées à la protection Slowloris
    When GET /waf/metrics
    Then les métriques contiennent:
      | waf_slowloris_blocked_total | connexions Slowloris fermées |
      | waf_slow_post_blocked_total | Slow POST fermés             |
      | waf_connections_per_ip_max  | max connexions vues par IP   |
      | waf_active_connections      | connexions actives total     |

  Scenario: Attaque Slowloris massivement distribuée
    Given 10 000 IPs distinctes ouvrent chacune 1 connexion Slowloris
    When chaque connexion dépasse header_timeout
    Then le serveur HTTP ferme chaque connexion à son expiration
    And la mémoire utilisée par les connexions pendantes est bornée
    And les visiteurs légitimes continuent à être servis
