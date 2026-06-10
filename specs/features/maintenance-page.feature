Feature: Page de Maintenance & Erreurs Custom
  En tant qu'administrateur du WAF,
  Je veux contrôler ce que voient les utilisateurs en cas d'indisponibilité
  Afin de maintenir une bonne expérience utilisateur même pendant les incidents.

  Background:
    Given le WAF est configuré avec une page de maintenance par défaut

  Scenario: Page de maintenance quand tous les upstreams sont DOWN
    Given tous les upstreams du domaine "example.com" sont DOWN
    When un visiteur envoie une requête vers example.com
    Then le WAF retourne HTTP 503
    And le body est la page de maintenance configurée pour ce domaine
    And le header Retry-After est présent avec la valeur configurée

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
    When l'upstream est indisponible
    Then le WAF sert la page de maintenance par défaut
    And la page contient le branding "Protected by GaetanDev.fr"
    And la page est visuellement cohérente avec la page de challenge

  Scenario: Mode maintenance forcé — opérateur déclenche manuellement
    Given un admin veut faire une maintenance
    When PATCH /waf/admin/config avec {"maintenance_mode": true}
    Then toutes les requêtes reçoivent HTTP 503 + page maintenance
    And les health checks continuent en arrière-plan (upstreams toujours monitorés)
    And un log event indique action="MAINTENANCE_MODE_ON"

  Scenario: Sortie du mode maintenance forcé
    When PATCH /waf/admin/config avec {"maintenance_mode": false}
    Then le trafic normal reprend
    Et un log event indique action="MAINTENANCE_MODE_OFF"

  Scenario: Page 403 personnalisée (visiteur bloqué)
    Given error_pages.403 = "/etc/waf/errors/403.html"
    When un visiteur est bloqué (blacklist ou score trop bas)
    Then le WAF sert la page 403 custom
    And le template contient {{.RequestID}} pour faciliter le support

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

  Scenario: Assets statiques servis même en mode maintenance
    Given le WAF est en mode maintenance forcé
    When un visiteur demande GET "/favicon.ico"
    Then le WAF proxifie vers l'upstream (si disponible)
    Note: Les assets favicon/robots.txt/etc. ne devraient pas montrer la maintenance
    Ou retourne l'asset depuis le cache local si configuré

  Scenario: Healthcheck WAF lui-même — répond toujours
    Given le WAF est en mode maintenance
    When GET /waf/health est appelé
    Then HTTP 200 est retourné avec {"status": "ok", "maintenance": true}
    Note: Le WAF lui-même fonctionne, c'est l'upstream qui est en maintenance

  Scenario: Retry-After cohérent avec upstream health check interval
    Given health_check.interval = 10s
    When la page de maintenance est servie
    Then Retry-After est environ égal à l'intervalle de health check (10s)
    Note: Indique aux clients quand retenter
