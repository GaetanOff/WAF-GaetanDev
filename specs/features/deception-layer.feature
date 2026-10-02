Feature: Deception Layer (Tarpit + Honeypot Content)
  En tant que WAF,
  Je veux piéger et ralentir les bots plutôt que de simplement les bloquer
  Afin de consommer leurs ressources et détecter leurs comportements plus précisément.

  # Les scénarios @deferred sont spécifiés mais NON implémentés (audit du
  # 2026-09-24, point 2.6) : ils ne sont pas un critère d'acceptation tant
  # que leur implémentation n'est pas planifiée (specs/tasks.md).
  # Injection de liens honeypot différée : la détection des chemins piégés
  # est assurée par honeypot_paths (antibot, 403), cf. internal/deception.

  Background:
    Given le WAF est configuré avec deception.enabled = true
    And deception.tarpit_max_connections = 500
    And deception.tarpit_chunks = 20
    And deception.tarpit_chunk_delay = "1s"

  # ── Tarpit ──────────────────────────────────────────────────────────────────

  Scenario: Requête classée TARPIT — tarpit activé
    Given une règle de tarpit est configurée pour trust_score < 15
    And un visiteur avec score = 8
    When ce visiteur envoie une requête GET
    Then le WAF retourne HTTP 200 avec Content-Type text/html
    And la réponse est envoyée en 20 morceaux (deception.tarpit_chunks), chacun vidé vers le client
    And les morceaux sont espacés de 1 s (deception.tarpit_chunk_delay)
    And la connexion reste ouverte environ 20 secondes

  Scenario: Tarpit — requête tarpitée journalisée et comptée TARPIT
    Given une requête classée TARPIT par le moteur de risque ou une règle
    When le tarpit lui sert sa réponse
    Then l'événement de sécurité porte action = "TARPIT"
    And la requête est comptée dans waf_requests_total{action="TARPIT"}
    And l'événement figure dans GET /waf/admin/events
    And requests_tarpitted de GET /waf/stats est incrémenté

  Scenario: Classification TARPIT sans couche de déception
    Given deception.enabled = false
    And une requête classée TARPIT par le moteur de risque
    When la requête est transmise à l'upstream
    Then l'événement de sécurité porte action = "PASS" et l'upstream_status réel

  Scenario: Tarpit — contenu HTML crédible simulé
    Given un bot est en mode tarpit
    Then la réponse HTML commence par un <!DOCTYPE html> valide
    And contient des éléments visuels factices (title, body, divs)
    And donne l'impression d'un chargement progressif

  Scenario: Tarpit — limite de connexions simultanées
    Given 500 connexions tarpitées sont déjà actives (limite atteinte)
    When un 501ème bot entre en condition de tarpit
    Then le WAF retourne HTTP 429 immédiatement au lieu du tarpit
    And l'événement de sécurité porte action = "TARPIT" et reason = "tarpit_saturated"
    And aucune goroutine supplémentaire n'est créée
    # Pas de métrique de connexions tarpitées (waf_tarpit_connections_total
    # différée) : waf_requests_total{action="TARPIT"} compte les réponses.

  Scenario: Tarpit — connexion abandonnée par le bot
    Given un bot est en mode tarpit depuis 15 secondes
    When le bot ferme la connexion TCP
    Then la goroutine de tarpit se termine immédiatement (context cancellation)
    And le slot de connexion est libéré

  Scenario: Tarpit — visiteurs légitimes non affectés
    Given un visiteur avec score = 75 (TRUSTED)
    When il envoie une requête
    Then aucun tarpit n'est appliqué
    And la réponse upstream est retournée immédiatement

  # ── Honeypot Content Injection ───────────────────────────────────────────────

  @deferred
  Scenario: Injection de liens honeypot dans une réponse HTML
    Given un domaine avec deception.injection.enabled = true
    And l'upstream retourne une réponse HTML text/html
    When le WAF proxifie la réponse
    Then le WAF injecte avant </body> un bloc de liens invisibles
    And les liens ont l'attribut rel="nofollow"
    And les liens pointent vers des paths /waf-trap/... avec tokens rotatifs

  @deferred
  Scenario: Lien honeypot suivi par un bot
    Given un lien honeypot injecté "/waf-trap/newsletter-abc123" a été ajouté à une page
    When un visiteur avec score = 65 envoie GET "/waf-trap/newsletter-abc123"
    Then le trust score est mis à 0
    And la requête reçoit HTTP 404 (ne pas révéler l'existence du honeypot)
    And un événement HONEYPOT est journalisé avec detail="injected_link_followed"

  @deferred
  Scenario: Humain ne suit pas les liens honeypot
    Given un lien honeypot invisible (display:none) est injecté dans une page
    When un visiteur humain navigue sur la page normalement
    Then le lien n'est pas visible dans l'interface
    And le visiteur ne le suit pas
    And aucun événement honeypot n'est déclenché

  @deferred
  Scenario: Injection uniquement sur Content-Type text/html
    Given l'upstream retourne une réponse JSON (application/json)
    When le WAF proxifie cette réponse
    Then aucune injection honeypot n'est effectuée
    And la réponse JSON est transmise intacte

  @deferred
  Scenario: Rotation hebdomadaire des tokens honeypot
    Given la semaine a changé
    When une nouvelle page HTML est servie
    Then les tokens des liens honeypot sont différents de ceux de la semaine précédente
    And les anciens tokens expirent (visites de bots qui ont crawlé la semaine précédente ne déclenchent plus honeypot)

  @deferred
  Scenario: Bot whitelisté — pas d'injection
    Given un Googlebot (user-agent whitelisté) visite la page
    When le WAF proxifie la réponse HTML
    Then aucun lien honeypot n'est injecté dans cette réponse

  @deferred
  Scenario: Injection ne casse pas le HTML valide
    Given l'upstream retourne du HTML valide avec </body></html> en fin
    When le WAF injecte le bloc honeypot
    Then le HTML résultant est toujours valide (</body> et </html> correctement positionnés)
    And la taille du body augmente de < 500 bytes
