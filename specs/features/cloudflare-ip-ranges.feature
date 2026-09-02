Feature: Plages IP Cloudflare et rafraîchissement automatique (FR-02)
  En tant qu'opérateur du WAF derrière Cloudflare,
  Je veux que la liste des plages IP Cloudflare reste à jour sans redéploiement
  Afin qu'un nouveau bloc IP annoncé par Cloudflare ne fasse pas rejeter du trafic légitime,
  Sans jamais qu'une liste erronée n'élargisse la confiance accordée à "CF-Connecting-IP".

  Background:
    Given le WAF est configuré avec cloudflare.trusted = true
    And la liste compilée dans le binaire contient les plages officielles connues

  Scenario: Rafraîchissement désactivé (défaut) — liste compilée
    Given cloudflare.auto_update_ranges = false
    When le WAF démarre
    Then aucune requête HTTP n'est émise vers cloudflare.com
    And la validation de "CF-Connecting-IP" utilise la liste compilée

  Scenario: Rafraîchissement réussi — adoption de la liste récupérée
    Given cloudflare.auto_update_ranges = true
    And cloudflare.update_interval = "24h"
    And les sources officielles renvoient 15 préfixes IPv4 et 7 préfixes IPv6 valides
    When le WAF démarre
    Then la liste en vigueur contient les 22 préfixes récupérés
    And la métrique "waf_cloudflare_ranges" vaut 22
    And "waf_cloudflare_ranges_update_total{result=\"success\"}" est incrémentée
    And un nouveau rafraîchissement a lieu 24h plus tard

  Scenario: Source injoignable — la liste en vigueur est conservée
    Given cloudflare.auto_update_ranges = true
    And la source IPv4 renvoie une erreur réseau
    When le rafraîchissement s'exécute
    Then le WAF continue de servir avec la liste précédente
    And "waf_cloudflare_ranges_update_total{result=\"error\"}" est incrémentée
    And le démarrage du WAF n'échoue pas

  Scenario: Liste dangereusement large — rejetée
    Given cloudflare.auto_update_ranges = true
    And la source IPv4 renvoie "0.0.0.0/0" parmi ses préfixes
    When le rafraîchissement s'exécute
    Then la liste récupérée est rejetée en entier
    And la liste en vigueur reste inchangée
    And une requête portant un "CF-Connecting-IP" forgé depuis une IP non-Cloudflare reçoit toujours HTTP 400

  Scenario: Réponse malformée — rejetée en entier
    Given cloudflare.auto_update_ranges = true
    And la source IPv4 renvoie une page HTML au lieu d'une liste de préfixes
    When le rafraîchissement s'exécute
    Then aucun préfixe n'est adopté
    And la liste en vigueur reste inchangée

  Scenario: Liste tronquée ou vide — rejetée
    Given cloudflare.auto_update_ranges = true
    And la source IPv6 renvoie une réponse vide
    When le rafraîchissement s'exécute
    Then la liste récupérée est rejetée
    And la liste en vigueur n'est jamais remplacée par une liste vide

  Scenario: Configuration contradictoire rejetée au démarrage
    Given cloudflare.trusted = false
    And cloudflare.auto_update_ranges = true
    When le WAF démarre
    Then le démarrage échoue avec une erreur de validation
    And l'erreur explique que les plages ne servent qu'à valider "CF-Connecting-IP"

  Scenario: Intervalle trop court rejeté au démarrage
    Given cloudflare.auto_update_ranges = true
    And cloudflare.update_interval = "5s"
    When le WAF démarre
    Then le démarrage échoue avec une erreur de validation nommant "cloudflare.update_interval"
