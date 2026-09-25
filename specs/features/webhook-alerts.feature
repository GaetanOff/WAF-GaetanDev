Feature: Alerting & Webhooks
  En tant qu'administrateur du WAF,
  Je veux être notifié en temps réel des événements de sécurité critiques
  Afin de réagir rapidement sans surveiller constamment les logs.

  # Les scénarios @deferred sont spécifiés mais NON implémentés (audit du
  # 2026-09-24, point 2.6) : ils ne sont pas un critère d'acceptation tant
  # que leur implémentation n'est pas planifiée (specs/tasks.md).
  # Triggers émis : block, circuit_breaker, honeypot, under_attack_start/end
  # (alert.schema.json). Configuration réelle : alerting.webhooks[].type/url,
  # alerting.cooldown, alerting.max_retries — le bloc alerts[] ci-dessous
  # (trigger, format, severity par webhook) est lui aussi différé.

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

  @deferred
  Scenario: Alerte DDoS envoyée sur Slack
    Given le trafic dépasse 200% du baseline (niveau Critical)
    When le trigger "ddos_detected" se déclenche
    Then un webhook HTTP POST est envoyé à l'URL Slack dans les 500ms
    And le body est au format Slack Incoming Webhook:
      {
        "text": "🚨 *WAF Alert* — DDoS detected on example.com",
        "attachments": [{"text": "Attack intensity: 250%..."}]
      }

  @deferred
  Scenario: Alerte upstream_down envoyée sur Discord
    Given upstream-A tombe (3 health checks échoués)
    When le trigger "upstream_down" se déclenche
    Then un webhook POST est envoyé à l'URL Discord
    And le body est au format Discord embed:
      {
        "embeds": [{"title": "WAF Alert — Upstream Down", "color": 15158332, ...}]
      }

  Scenario: Alerte Discord enrichie (embed coloré avec champs)
    Given un sink de type "discord" configuré
    When un événement honeypot déclenche une alerte
    Then le body est un embed Discord (clé "embeds") et non un simple "content"
    And l'embed a une couleur selon la sévérité (rouge=critical, orange=warning, bleu=info)
    And l'embed a un titre lisible avec emoji (ex: "🍯 Honeypot déclenché")
    And l'embed liste en champs : Domaine, Action, IP, Pays, Méthode, Chemin, Raison, Score
    And l'embed porte un timestamp et un footer "WAF GaetanDev • req <request_id>"
    # Slack reçoit l'équivalent en attachment coloré ; le générique reçoit l'Alert JSON enrichie.

  Scenario: Alerte generic HTTP — payload JSON conforme au schema
    Given un visiteur touche un chemin honeypot
    When le trigger "honeypot" se déclenche
    Then un webhook POST est envoyé
    And le body JSON est conforme à schemas/alert.schema.json
    And il contient les champs: id (UUID v4), timestamp, trigger, severity, domain, title, message

  @deferred
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
    Given le trigger "block" se déclenche toutes les 5 secondes pour le même domaine
    Then le WAF envoie seulement 1 alerte par alerting.cooldown (défaut: 5m) et par trigger + domaine
    And les transitions under_attack_start / under_attack_end ne sont jamais retenues par le cooldown

  @deferred
  Scenario: Alerte de retour à la normale
    Given une alerte "upstream_down" a été envoyée pour upstream-A
    When upstream-A revient (3 health checks réussis)
    Then une alerte "upstream_recovered" est envoyée automatiquement
    And contient le temps de downtime en secondes

  @deferred
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

  @deferred
  Scenario: Test de webhook via API admin
    When POST /waf/admin/alerts/test avec body {"trigger": "ddos_detected"}
    Then le WAF envoie immédiatement un webhook test
    And la réponse API indique si le webhook a répondu (HTTP 200 ou erreur)
    Note: Utile pour valider la configuration sans attendre une vraie attaque

  Scenario: Métriques alertes
    Given un sink qui répond HTTP 200 et un sink qui répond HTTP 500
    When un événement honeypot déclenche une alerte
    And GET /waf/metrics
    Then les métriques contiennent:
      | waf_alerts_sent_total{trigger="honeypot"}   | 1 (livraison acceptée) |
      | waf_alerts_failed_total{trigger="honeypot"} | 1 (livraison abandonnée) |
      | waf_alerts_pending                          | alertes en attente d'envoi |
