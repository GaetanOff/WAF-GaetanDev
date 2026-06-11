Feature: Terminaison TLS par domaine (sélection par SNI)
  En tant qu'administrateur du WAF,
  Je veux présenter un certificat TLS distinct par domaine, sélectionné par SNI,
  Afin d'intercaler le WAF devant plusieurs vhosts en réutilisant les certificats existants.

  # Spec : requirements-ops.md FR-33 ; décision : ADR-017 ; schéma : config.schema.json
  # Statut : draft — implémentation différée.

  Background:
    Given le WAF est configuré avec server.tls.enabled = true
    And server.tls.listen = ":443"
    And server.tls.min_version = "1.2"
    And le domaine "alpha.example.com" a un tls.cert_file et tls.key_file valides
    And le domaine "beta.example.com" a un tls.cert_file et tls.key_file valides

  Scenario: SNI connu — le certificat du domaine est présenté
    Given un client ouvre une connexion TLS avec SNI "alpha.example.com"
    When le handshake TLS se déroule
    Then le WAF présente le certificat de "alpha.example.com"
    And la connexion est établie

  Scenario: SNI d'un autre domaine — le bon certificat est présenté
    Given un client ouvre une connexion TLS avec SNI "beta.example.com"
    When le handshake TLS se déroule
    Then le WAF présente le certificat de "beta.example.com"
    And le certificat de "alpha.example.com" n'est pas présenté

  Scenario: Domaine wildcard — correspondance par SNI
    Given le domaine "*.api.example.com" a un certificat wildcard valide
    And un client ouvre une connexion TLS avec SNI "v1.api.example.com"
    When le handshake TLS se déroule
    Then le WAF présente le certificat wildcard de "*.api.example.com"

  Scenario: SNI inconnu avec certificat par défaut configuré
    Given server.tls.cert_file et server.tls.key_file sont configurés (certificat par défaut)
    And un client ouvre une connexion TLS avec SNI "inconnu.example.org"
    When le handshake TLS se déroule
    Then le WAF présente le certificat par défaut
    And la connexion est établie

  Scenario: SNI inconnu sans certificat par défaut — handshake refusé
    Given aucun certificat par défaut n'est configuré
    And un client ouvre une connexion TLS avec SNI "inconnu.example.org"
    When le handshake TLS se déroule
    Then le WAF refuse le handshake ("unrecognized_name")
    And aucun certificat arbitraire n'est présenté

  Scenario: Démarrage fail-fast — fichier de certificat manquant
    Given le domaine "gamma.example.com" référence un tls.cert_file inexistant
    When le WAF démarre
    Then le WAF refuse de démarrer avec une erreur de configuration explicite
    And aucun vhost n'est servi avec un certificat cassé

  Scenario: Démarrage fail-fast — la clé ne correspond pas au certificat
    Given le domaine "delta.example.com" a un tls.key_file qui ne correspond pas au tls.cert_file
    When le WAF démarre
    Then le WAF refuse de démarrer avec une erreur de configuration explicite

  Scenario: TLS 1.0 refusé, TLS 1.3 accepté
    Given server.tls.min_version = "1.2"
    When un client tente une connexion en TLS 1.0 avec SNI "alpha.example.com"
    Then la connexion est refusée (version non supportée)
    When un client se connecte en TLS 1.3 avec SNI "alpha.example.com"
    Then la connexion est établie normalement

  Scenario: Redirection HTTP vers HTTPS
    Given server.tls.redirect_http = true
    When un client envoie une requête HTTP sur "http://alpha.example.com/page"
    Then le WAF répond une redirection 301 vers "https://alpha.example.com/page"

  Scenario: Redirection HTTP vers HTTPS — Host inconnu rejeté (open-redirect)
    Given server.tls.redirect_http = true
    When un client envoie une requête HTTP avec Host "evil.com" sur le port d'écoute
    Then le WAF répond 400 Bad Request sans effectuer de redirection

  Scenario: Redirection HTTP vers HTTPS — chemin double-slash neutralisé
    Given server.tls.redirect_http = true
    When un client envoie une requête HTTP sur "http://alpha.example.com" avec chemin "//evil.com/x"
    Then le WAF répond une redirection 301 dont l'URL cible commence par "https://alpha.example.com/"
    And l'URL cible ne contient pas "evil.com" comme host

  Scenario: Inspection L7 après terminaison TLS
    Given un client établit une connexion TLS valide avec SNI "alpha.example.com"
    When il envoie une requête HTTP applicative
    Then la requête traverse les middlewares de sécurité du WAF (challenge, rate limit, score)
    And est transmise à l'upstream du domaine en clair sur le réseau interne

  Scenario: Métrique d'expiration par domaine
    When GET /waf/metrics
    Then la métrique waf_tls_cert_expiry_seconds{domain="alpha.example.com"} est présente
    And la métrique waf_tls_cert_expiry_seconds{domain="beta.example.com"} est présente
