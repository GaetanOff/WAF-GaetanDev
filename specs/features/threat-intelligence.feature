Feature: Intégration Threat Intelligence
  En tant que WAF,
  Je veux enrichir les décisions de sécurité avec des données de réputation externes
  Afin de détecter les acteurs malveillants connus avant même qu'ils agissent.

  # Contrat : bloc `threat_intel` de config.schema.json (enabled, cache_ttl,
  # blocklist_cidrs, suspect_cidrs, abuseipdb.{enabled,url,api_key}), FR-13.
  # Le vérificateur retient par IP un verdict {niveau, raison} :
  #   critique    → déclencheur déterministe threat_intel_critical (BLOCK, FR-35)
  #   malveillant → trust score plafonné à 20
  #   suspect     → trust score plafonné à 35
  # Les scénarios @deferred sont spécifiés mais NON implémentés (audit du
  # 2026-09-24, point 4.1) : ils ne sont pas un critère d'acceptation tant que
  # leur implémentation n'est pas planifiée (specs/tasks.md).

  Background:
    Given le WAF est configuré avec threat_intel.enabled = true
    And threat_intel.abuseipdb.enabled = true

  Scenario: IP avec score AbuseIPDB ≥ 80 — déclencheur déterministe, BLOCK
    Given l'IP "185.220.101.1" a un score AbuseIPDB de 92 (verdict en cache)
    When cette IP envoie une requête
    Then la requête porte le déclencheur déterministe "threat_intel_critical"
    And elle est bloquée (HTTP 403) sans corroboration, avec reason="abuseipdb_critical"
    And c'est le moteur de risque qui bloque, ou le middleware de trust score sans moteur

  Scenario: IP avec score AbuseIPDB entre 50 et 79 — trust score plafonné
    Given l'IP "45.56.78.90" a un score AbuseIPDB de 55 (verdict en cache)
    And son trust score est 80
    When cette IP envoie une requête
    Then son trust score est abaissé à 20 (jamais relevé s'il est déjà plus bas)
    And reason="abuseipdb_malicious"
    And le visiteur est challengé (20 < trust.challenge_threshold)

  Scenario: IP propre AbuseIPDB — pas d'impact
    Given l'IP "203.0.113.42" a un score AbuseIPDB de 10
    When cette IP envoie une requête
    Then aucun plafond ni déclencheur n'est appliqué par la réputation

  Scenario: Plages locales — blocklist et plages suspectes
    Given threat_intel.blocklist_cidrs = ["192.168.100.0/24"]
    And threat_intel.suspect_cidrs = ["10.0.0.0/8"]
    When l'IP "192.168.100.1" envoie une requête
    Then son trust score est plafonné à 20 avec reason="blocklist"
    When l'IP "10.9.9.9" envoie une requête
    Then son trust score est plafonné à 35 avec reason="suspect_range"
    # Des plages Tor ou datacenter ne sont prises en compte que saisies ici en CIDR.

  Scenario: Cache — pas d'appel API sur requête répétée
    Given l'IP "185.220.101.1" a déjà été résolue (verdict en cache, threat_intel.cache_ttl)
    When la même IP envoie 100 requêtes supplémentaires dans l'heure
    Then aucun appel API AbuseIPDB n'est effectué pour ces requêtes
    And le verdict du cache est utilisé

  Scenario: Lookup asynchrone — requête non bloquée
    Given l'IP "10.20.30.40" est inconnue (pas en cache)
    When elle envoie sa première requête
    Then la requête est traitée immédiatement comme « propre »
    And la résolution est confiée au pool borné de workers en arrière-plan
    And le verdict est disponible pour les requêtes suivantes de cette IP

  Scenario: Service AbuseIPDB en échec — WAF fonctionnel
    Given l'API AbuseIPDB répond en erreur ou est injoignable (timeout 3 s)
    When une IP inconnue envoie une requête
    Then le WAF continue à fonctionner normalement, sans attendre le lookup
    And le verdict de l'IP est « propre » (mis en cache pour cache_ttl)
    And les décisions se basent uniquement sur les autres signaux disponibles

  @deferred
  Scenario: Métrique d'erreur AbuseIPDB
    Given l'API AbuseIPDB est inaccessible
    When un lookup échoue
    Then une métrique waf_threat_intel_errors_total{source="abuseipdb"} est incrémentée

  @deferred
  Scenario: Tor exit node détecté
    Given l'IP "199.87.154.255" est un exit node Tor connu
    When cette IP envoie une requête
    Then le trust score est décrémenté de 25
    And l'événement est journalisé avec reason="tor_exit_node"

  @deferred
  Scenario: Mise à jour automatique de la liste Tor
    Given la liste Tor est configurée pour être mise à jour toutes les heures
    When 1 heure s'écoule depuis le dernier fetch
    Then le WAF refetch https://check.torproject.org/torbulkexitlist
    And la nouvelle liste remplace l'ancienne atomiquement

  @deferred
  Scenario: IP dans un ASN hosting (AWS, GCP, DigitalOcean)
    Given l'IP "35.180.0.1" appartient à l'ASN AS16509 (Amazon AWS)
    When cette IP envoie une requête
    Then le trust score est décrémenté de 10 (asn_type = hosting)
    And le log indique reason="asn_datacenter" avec asn="AS16509"

  @deferred
  Scenario: ASN en whitelist — pas de pénalité
    Given l'ASN "AS13335" (Cloudflare) est dans la whitelist ASN
    When une IP Cloudflare envoie une requête
    Then aucun delta n'est appliqué pour ce signal ASN

  @deferred
  Scenario: Feed local YAML rechargeable
    Given un feed local YAML contient l'IP "192.168.100.1" avec score 100
    When le feed est modifié sur disque
    Then il est rechargé sans redémarrage
    And la source est journalisée comme "local_feed"

  @deferred
  Scenario: Statistiques threat intel via API admin
    When GET /waf/admin/threat-intel/stats
    Then la réponse contient:
      | cache_hit_rate    | ratio hits/lookups  |
      | api_calls_today   | appels AbuseIPDB    |
      | tor_nodes_count   | taille liste Tor    |
      | asn_entries_count | entrées ASN DB      |
