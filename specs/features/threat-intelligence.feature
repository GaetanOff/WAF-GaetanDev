Feature: Intégration Threat Intelligence
  En tant que WAF,
  Je veux enrichir les décisions de sécurité avec des données de réputation externes
  Afin de détecter les acteurs malveillants connus avant même qu'ils agissent.

  Background:
    Given le WAF est configuré avec threat_intel.enabled = true
    And threat_intel.abuseipdb.enabled = true
    And threat_intel.tor.enabled = true
    And threat_intel.asn.enabled = true

  Scenario: IP avec score AbuseIPDB élevé — trust score décrémenté
    Given l'IP "185.220.101.1" a un score AbuseIPDB de 92
    When cette IP envoie sa première requête
    Then le trust score est décrémenté de 40 (score ≥ 80)
    And l'événement est journalisé avec reason="abuseipdb_high_confidence"
    And le visiteur reçoit un challenge JS

  Scenario: IP avec score AbuseIPDB moyen
    Given l'IP "45.56.78.90" a un score AbuseIPDB de 55
    When cette IP envoie une requête
    Then le trust score est décrémenté de 20 (score ≥ 50)
    And le visiteur est challengé si son score descend sous le seuil

  Scenario: IP propre AbuseIPDB — pas d'impact
    Given l'IP "203.0.113.42" a un score AbuseIPDB de 10
    When cette IP envoie une requête
    Then aucun delta n'est appliqué par le module AbuseIPDB

  Scenario: Cache AbuseIPDB — pas d'appel API sur requête répétée
    Given l'IP "185.220.101.1" a déjà été lookupée (résultat en cache)
    When la même IP envoie 100 requêtes supplémentaires dans l'heure
    Then aucun appel API AbuseIPDB n'est effectué pour ces requêtes
    And le résultat du cache est utilisé

  Scenario: Lookup AbuseIPDB asynchrone — requête non bloquée
    Given l'IP "10.20.30.40" est inconnue (pas en cache)
    When elle envoie sa première requête
    Then la requête est traitée immédiatement avec le score existant (sans réputation)
    And le lookup AbuseIPDB est déclenché en arrière-plan
    And le résultat est disponible pour la deuxième requête de cette IP

  Scenario: Tor exit node détecté
    Given l'IP "199.87.154.255" est un exit node Tor connu
    When cette IP envoie une requête
    Then le trust score est décrémenté de 25
    And l'événement est journalisé avec reason="tor_exit_node"
    And le visiteur est challengé

  Scenario: Mise à jour automatique de la liste Tor
    Given la liste Tor est configurée pour être mise à jour toutes les heures
    When 1 heure s'écoule depuis le dernier fetch
    Then le WAF refetch https://check.torproject.org/torbulkexitlist
    And la nouvelle liste remplace l'ancienne atomiquement
    And aucune interruption de service n'a lieu pendant le rechargement

  Scenario: IP dans un ASN hosting (AWS, GCP, DigitalOcean)
    Given l'IP "35.180.0.1" appartient à l'ASN AS16509 (Amazon AWS)
    When cette IP envoie une requête
    Then le trust score est décrémenté de 10 (asn_type = hosting)
    And le log indique reason="asn_datacenter" avec asn="AS16509"

  Scenario: ASN en whitelist — pas de pénalité
    Given l'ASN "AS13335" (Cloudflare) est dans la whitelist ASN
    When une IP Cloudflare envoie une requête
    Then aucun delta n'est appliqué pour ce signal ASN

  Scenario: Feed local YAML — IP malveillante custom
    Given un feed local contient l'IP "192.168.100.1" avec score 100
    When cette IP envoie une requête
    Then le trust score est décrémenté conformément au feed local
    And la source est journalisée comme "local_feed"

  Scenario: Service AbuseIPDB down — WAF fonctionne en mode dégradé
    Given l'API AbuseIPDB est inaccessible (timeout réseau)
    When une IP inconnue envoie une requête
    Then le WAF continue à fonctionner normalement
    And aucun lookup n'est tenté pour éviter les délais
    And une métrique waf_threat_intel_errors_total{source="abuseipdb"} est incrémentée
    And les décisions se basent uniquement sur les autres signaux disponibles

  Scenario: Statistiques threat intel via API admin
    When GET /waf/admin/threat-intel/stats
    Then la réponse contient:
      | cache_hit_rate    | ratio hits/lookups  |
      | api_calls_today   | appels AbuseIPDB    |
      | tor_nodes_count   | taille liste Tor    |
      | asn_entries_count | entrées ASN DB      |
