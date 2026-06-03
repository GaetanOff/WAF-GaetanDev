Feature: Alerting & Webhooks
  En tant qu'administrateur du WAF,
  Je veux être notifié en temps réel des événements de sécurité critiques
  Afin de réagir rapidement sans surveiller constamment les logs.

  Background:
    Given le WAF est configuré avec:
      alerts:
        - trigger: ddos_detected
          url: "https://hooks.slack.com/services/T00/B00/xxx"
          format: slack
          severity: ["warning", "critical"]
        - trigger: upstream_down
          url: "https://discord.com/api/webhooks/xxx/yyy"
          format: discord
          severity: ["critical"]
        - trigger: honeypot_triggered
          url: "https://my-siem.example.com/webhook"
          format: generic
          severity: ["info", "warning", "critical"]

  Scenario: Alerte DDoS envoyée sur Slack
    Given le trafic dépasse 200% du baseline (niveau Critical)
    When le trigger "ddos_detected" se déclenche
    Then un webhook HTTP POST est envoyé à l'URL Slack dans les 500ms
    And le body est au format Slack Incoming Webhook:
      {
        "text": "🚨 *WAF Alert* — DDoS detected on example.com",
        "attachments": [{"text": "Attack intensity: 250%..."}]
      }

  Scenario: Alerte upstream_down envoyée sur Discord
    Given upstream-A tombe (3 health checks échoués)
    When le trigger "upstream_down" se déclenche
    Then un webhook POST est envoyé à l'URL Discord
    And le body est au format Discord embed:
      {
        "embeds": [{"title": "WAF Alert — Upstream Down", "color": 15158332, ...}]
      }

  Scenario: Alerte generic HTTP — payload JSON conforme au schema
    Given un visiteur touche un chemin honeypot
    When le trigger "honeypot_triggered" se déclenche
    Then un webhook POST est envoyé
    And le body JSON est conforme à schemas/alert.schema.json
    Et contient les champs: id, timestamp, trigger, severity, domain, title, message, data

  Scenario: Retry en cas d'échec du webhook
    Given l'URL de webhook retourne HTTP 500 lors du premier envoi
    When le WAF retente avec backoff exponentiel
    Then le 2ème envoi est effectué après 1 seconde
    And le 3ème envoi après 5 secondes (si le 2ème échoue)
    And le 4ème envoi après 25 secondes (si le 3ème échoue)
    And après 3 tentatives échouées, l'alerte est abandonnée
    And la métrique waf_alerts_failed_total est incrémentée

  Scenario: Webhook timeout — pas de blocage du pipeline WAF
    Given l'URL de webhook ne répond pas (timeout réseau)
    When le webhook est envoyé de manière asynchrone
    Then la requête cliente est traitée et répond normalement
    And le webhook est géré en arrière-plan dans sa propre goroutine

  Scenario: Déduplication — pas de spam d'alertes
    Given le trigger "ddos_detected" est actif (attaque en cours)
    When le trigger se déclenche toutes les 5 secondes
    Then le WAF envoie seulement 1 alerte toutes les alerting.cooldown_seconds (défaut: 60s)
    And la 2ème alerte n'est pas envoyée si le cooldown n'est pas écoulé

  Scenario: Alerte de retour à la normale
    Given une alerte "upstream_down" a été envoyée pour upstream-A
    When upstream-A revient (3 health checks réussis)
    Then une alerte "upstream_recovered" est envoyée automatiquement
    And contient le temps de downtime en secondes

  Scenario: Alerte cert TLS expirant dans 7 jours
    Given un certificat TLS pour "example.com" expire dans 6 jours
    When le checker de certificat s'exécute (toutes les heures)
    Then l'alerte "tls_cert_expiring" est envoyée avec:
      - cert_domain: "example.com"
      - cert_days_remaining: 6
      - severity: "critical"

  Scenario: Webhook désactivé — aucune alerte
    Given alerts: [] (liste vide)
    When n'importe quel trigger se déclenche
    Then aucun webhook n'est envoyé
    And aucune erreur n'est loggée

  Scenario: Test de webhook via API admin
    When POST /waf/admin/alerts/test avec body {"trigger": "ddos_detected"}
    Then le WAF envoie immédiatement un webhook test
    And la réponse API indique si le webhook a répondu (HTTP 200 ou erreur)
    Note: Utile pour valider la configuration sans attendre une vraie attaque

  Scenario: Métriques alertes
    When GET /waf/metrics
    Then les métriques contiennent:
      | waf_alerts_sent_total{trigger}   | par type de trigger |
      | waf_alerts_failed_total{trigger} | échecs d'envoi      |
      | waf_alerts_pending_total         | en attente d'envoi  |
