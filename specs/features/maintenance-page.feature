Feature: Page de Maintenance & Erreurs Custom
  En tant qu'administrateur du WAF,
  Je veux contrôler ce que voient les utilisateurs en cas d'indisponibilité
  Afin de maintenir une bonne expérience utilisateur même pendant les incidents.

  # Les scénarios @deferred sont spécifiés mais NON implémentés (audit du
  # 2026-10-01) : ils ne sont pas un critère d'acceptation tant que leur
  # implémentation n'est pas planifiée (specs/tasks.md).
  # Contrat : maintenance.enabled et maintenance.error_pages (config.schema.json),
  # lus au démarrage ; pages brandées générées par le WAF, sans template
  # opérateur ; Retry-After fixe à 300 s (FR-32).

  Background:
    Given le WAF est configuré avec une page de maintenance par défaut

  Scenario: Mode maintenance — 503 pour tout le trafic hors endpoints internes
    Given maintenance.enabled = true au démarrage
    When un visiteur envoie GET "/" vers example.com
    Then le WAF retourne HTTP 503 avec la page de maintenance brandée
    And le header Retry-After vaut "300"
    And la requête n'est pas transmise à l'upstream
    When un visiteur demande GET "/favicon.ico"
    Then le WAF retourne aussi HTTP 503 (le mode maintenance précède le bypass des assets)

  @deferred
  Scenario: Page de maintenance quand tous les upstreams sont DOWN
    Given tous les upstreams du domaine "example.com" sont DOWN
    When un visiteur envoie une requête vers example.com
    Then le WAF retourne HTTP 503
    And le body est la page de maintenance configurée pour ce domaine
    And le header Retry-After est présent avec la valeur configurée
    # Aujourd'hui : 502 "no healthy upstream", brandé si error_pages (FR-25).

  @deferred
  Scenario: Page de maintenance custom par domaine
    Given maintenance_page.path = "/etc/waf/maintenance/example.html" pour example.com
    When l'upstream est indisponible
    Then le WAF sert ce fichier HTML spécifique
    And le template est rendu avec les variables injectées:
      | {{.StatusCode}} | 503              |
      | {{.Domain}}     | example.com      |
      | {{.RetryAfter}} | 60               |
      | {{.RequestID}}  | uuid-de-la-req   |

  Scenario: Page de maintenance par défaut (branding GaetanDev.fr)
    Given aucune page de maintenance custom n'est configurée
    When le WAF est en mode maintenance (maintenance.enabled = true)
    Then le WAF sert la page de maintenance par défaut
    And la page contient le branding "Protected by GaetanDev.fr"
    And la page est visuellement cohérente avec la page de challenge

  Scenario: Identité visuelle des pages d'erreur/blocage brandées
    Given error_pages activé
    When le WAF sert une page brandée par défaut (403, 429, 503, 502…)
    Then la page reprend le design de la page d'accès (carte centrée, badge, dark mode auto)
    And l'icône est une croix rouge — miroir de la coche verte de la page d'accès autorisé
    And l'animation reprend le même effet (apparition « pop » du cercle + tracé du trait)
    And le rendu est 100 % CSS inline, sans ressource externe ni JavaScript
    And l'animation est neutralisée si prefers-reduced-motion: reduce
    And la carte suit le thème système via prefers-color-scheme (clair/sombre)

  @deferred
  Scenario: Mode maintenance forcé — opérateur déclenche manuellement
    Given un admin veut faire une maintenance
    When PATCH /waf/admin/config avec {"maintenance_mode": true}
    Then toutes les requêtes reçoivent HTTP 503 + page maintenance
    And les health checks continuent en arrière-plan (upstreams toujours monitorés)
    And un log event indique action="MAINTENANCE_MODE_ON"

  @deferred
  Scenario: Sortie du mode maintenance forcé
    When PATCH /waf/admin/config avec {"maintenance_mode": false}
    Then le trafic normal reprend
    Et un log event indique action="MAINTENANCE_MODE_OFF"

  @deferred
  Scenario: Page 403 personnalisée (visiteur bloqué)
    Given error_pages.403 = "/etc/waf/errors/403.html"
    When un visiteur est bloqué (blacklist ou score trop bas)
    Then le WAF sert la page 403 custom
    And le template contient {{.RequestID}} pour faciliter le support

  @deferred
  Scenario: Page 429 personnalisée avec compte à rebours
    Given error_pages.429 = "/etc/waf/errors/429.html"
    And le template contient {{.RetryAfter}}
    When un visiteur déclenche le rate limit (RetryAfter = 30s)
    Then le WAF sert la page 429 avec "Réessayez dans 30 secondes"

  Scenario: Page d'erreur brandée servie à une navigation de navigateur
    Given error_pages activé
    When un visiteur navigateur (Accept "text/html") reçoit une erreur 403
    Then le corps d'erreur est remplacé par la page HTML brandée

  Scenario: Appel API — le corps d'erreur d'origine est préservé
    Given error_pages activé
    When un appel API (Accept "application/json") reçoit une erreur 401 avec un corps JSON
    Then le WAF ne remplace PAS le corps : le JSON d'origine est renvoyé tel quel
    # fetch/axios doivent pouvoir parser l'erreur ; une page HTML les casserait.

  Scenario: Origine down — le 502 HTML générique est brandé
    Given error_pages activé
    And l'origine (ex: derrière OpenResty) renvoie un "502 Bad Gateway" en text/html
    When un visiteur navigateur (Accept "text/html") reçoit ce 502
    Then le WAF remplace la page passerelle générique par sa page brandée
    # Les 5xx sont brandés même en HTML : ce n'est pas du contenu applicatif.

  Scenario: Origine en erreur avec un corps compressé — la page brandée est servie en clair
    Given error_pages activé
    And l'origine renvoie un 500 avec "Content-Encoding: gzip", un ETag et un Last-Modified
    When un visiteur navigateur (Accept "text/html") reçoit ce 500
    Then le WAF sert sa page brandée non compressée
    And la réponse ne porte ni Content-Encoding, ni Content-Range, ni ETag, ni Last-Modified
    # Ces en-têtes décrivaient le corps d'origine ; sur la page brandée, un
    # Content-Encoding recopié fait échouer le décodage du navigateur.

  Scenario: Erreur 4xx JSON d'une API — préservée même pour une navigation
    Given error_pages activé
    When une requête avec Accept "text/html,*/*" reçoit une erreur 422 en application/json
    Then le WAF ne remplace PAS le corps : le JSON d'origine est renvoyé tel quel
    # Seuls les 4xx en texte brut (refus du WAF) sont brandés.

  Scenario: Page 4xx HTML légitime d'une appli — préservée
    Given error_pages activé
    When une appli renvoie une page 404 personnalisée en text/html
    Then le WAF ne la remplace pas (les 4xx HTML légitimes sont préservés)

  @deferred
  Scenario: Assets statiques servis même en mode maintenance
    Given le WAF est en mode maintenance forcé
    When un visiteur demande GET "/favicon.ico"
    Then le WAF proxifie vers l'upstream (si disponible)
    Note: Les assets favicon/robots.txt/etc. ne devraient pas montrer la maintenance
    Ou retourne l'asset depuis le cache local si configuré

  Scenario: Healthcheck et métriques du WAF — répondent toujours
    Given le WAF est en mode maintenance
    When GET /waf/health est appelé
    Then HTTP 200 est retourné avec {"status": "ok"}
    When GET /waf/metrics est appelé
    Then les métriques Prometheus sont servies (pas de page 503)
    Note: Le WAF lui-même fonctionne ; un champ "maintenance" dans /waf/health est différé

  @deferred
  Scenario: Retry-After cohérent avec upstream health check interval
    Given health_check.interval = 10s
    When la page de maintenance est servie
    Then Retry-After est environ égal à l'intervalle de health check (10s)
    Note: Indique aux clients quand retenter
