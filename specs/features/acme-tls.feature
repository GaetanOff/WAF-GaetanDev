Feature: TLS Termination & ACME / Let's Encrypt
  En tant qu'administrateur du WAF,
  Je veux que le WAF gère automatiquement les certificats TLS
  Afin de ne jamais avoir d'expiration de certificat causant une interruption de service.

  # Contrat : bloc `acme` de config.schema.json (enabled, domains, email,
  # cache_dir, tls_listen, http_challenge_listen), FR-31. Il n'existe pas de
  # sous-bloc `server.tls.acme` : `acme.enabled` et `server.tls.enabled`
  # (certificats statiques par SNI, per-domain-tls.feature) sont mutuellement
  # exclusifs, refusés ensemble par la validation de configuration.
  # Les scénarios @deferred sont spécifiés mais NON implémentés (audits du
  # 2026-09-24, point 2.6, et du 2026-09-25, phase 21) : ils ne sont pas un
  # critère d'acceptation tant que leur implémentation n'est pas planifiée
  # (specs/tasks.md). Expiration : seule la jauge waf_tls_cert_expiry_seconds
  # (timestamp NotAfter des certificats statiques de server.tls, publiée au
  # démarrage) existe ; les certificats ACME n'y figurent pas.

  Background:
    Given le WAF est configuré avec acme.enabled = true
    And acme.email = "admin@example.com"
    And acme.domains = ["example.com", "www.example.com"]
    And acme.tls_listen = ":443" et acme.http_challenge_listen = ":80"
    And server.tls.enabled = false

  Scenario: ACME et certificats statiques sur le même listener — démarrage refusé
    Given acme.enabled = true et server.tls.enabled = true
    When le WAF démarre
    Then la configuration est refusée ("server.tls.enabled and acme.enabled are mutually exclusive on the same listener")

  Scenario: ACME sans domaine — démarrage refusé
    Given acme.enabled = true et acme.domains = []
    When le WAF démarre
    Then la configuration est refusée ("acme.domains must not be empty when enabled")

  Scenario: Premier handshake — certificat obtenu automatiquement
    Given aucun certificat n'existe encore pour example.com dans acme.cache_dir
    When un client ouvre une connexion TLS avec SNI "example.com" sur acme.tls_listen
    Then le WAF obtient le certificat auprès de Let's Encrypt (TLS-ALPN-01 ou HTTP-01)
    And le certificat est stocké dans acme.cache_dir
    And la connexion est établie avec ce certificat

  Scenario: SNI hors de acme.domains — aucun certificat demandé
    When un client ouvre une connexion TLS avec SNI "evil.example.org"
    Then aucune demande ACME n'est émise pour ce nom
    And le handshake est refusé

  Scenario: Renouvellement automatique — 30 jours avant expiration
    Given le certificat de example.com expire dans 29 jours
    When un client ouvre une connexion TLS avec SNI "example.com"
    Then le WAF initie le renouvellement automatiquement (≤ 30 jours avant expiration)
    And l'ancien certificat reste servi pendant le renouvellement
    And le nouveau certificat est pris en compte sans redémarrage

  Scenario: Rotation de certificat sans interruption de service
    Given un nouveau certificat vient d'être obtenu
    When le WAF active le nouveau certificat
    Then les connexions TLS existantes continuent avec l'ancien certificat
    And les nouvelles connexions utilisent le nouveau certificat
    And aucune connexion n'est interrompue

  Scenario: Challenge ACME HTTP-01 hors du pipeline de sécurité
    When Let's Encrypt fait une requête GET "/.well-known/acme-challenge/<token>" sur acme.http_challenge_listen
    Then la réponse ACME correcte est retournée
    And la requête ne traverse aucun middleware de sécurité (whitelist, challenge, rate limit)
    # Le listener HTTP-01 est un serveur distinct du pipeline public.

  Scenario: Requête HTTP ordinaire sur le listener HTTP-01 — redirection HTTPS
    When un client envoie GET "http://example.com/page" sur acme.http_challenge_listen
    Then le WAF répond une redirection vers "https://example.com/page"

  Scenario: TLS 1.2 minimum, TLS 1.0/1.1 refusés
    When un client tente de se connecter en TLS 1.0
    Then la connexion est refusée (version non supportée)
    When un client se connecte en TLS 1.3
    Then la connexion est établie normalement
    # En mode ACME le plancher est fixé à TLS 1.2 ; server.tls.min_version et
    # server.tls.cipher_suites ne s'appliquent qu'aux certificats statiques
    # (per-domain-tls.feature).

  @deferred
  Scenario: Métrique d'expiration des certificats ACME
    When GET /waf/metrics
    Then la métrique waf_tls_cert_expiry_seconds{domain="example.com"} est présente
    And elle suit le certificat ACME courant, renouvellements compris

  @deferred
  Scenario: Alerte certificat expirant dans moins de 7 jours
    Given le certificat expire dans 5 jours
    And le renouvellement automatique a échoué (Let's Encrypt indisponible)
    When le checker s'exécute
    Then un webhook d'alerte "tls_cert_expiring" est envoyé avec severity="critical"
    And la métrique waf_tls_cert_expiry_seconds{domain="example.com"} est mise à jour
    And le WAF continue de fonctionner avec le certificat existant (même si expirant)

  @deferred
  Scenario: Hot-reload des certificats statiques (SIGHUP)
    Given acme.enabled = false et server.tls.enabled = true
    And les fichiers cert.pem et key.pem ont été mis à jour manuellement
    When le WAF reçoit SIGHUP
    Then le nouveau certificat est chargé sans redémarrage
    And les nouvelles connexions TLS utilisent le nouveau certificat
