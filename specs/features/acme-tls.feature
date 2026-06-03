Feature: TLS Termination & ACME / Let's Encrypt
  En tant qu'administrateur du WAF,
  Je veux que le WAF gère automatiquement les certificats TLS
  Afin de ne jamais avoir d'expiration de certificat causant une interruption de service.

  Background:
    Given le WAF est configuré avec server.tls.enabled = true
    And server.tls.acme.enabled = true
    And server.tls.acme.email = "admin@example.com"
    And server.tls.acme.domains = ["example.com", "www.example.com"]

  Scenario: Premier démarrage — certificat obtenu automatiquement
    Given aucun certificat n'existe encore pour example.com
    When le WAF démarre pour la première fois
    Then le WAF initie la procédure ACME HTTP-01 avec Let's Encrypt
    And le challenge /.well-known/acme-challenge/ bypass tous les middlewares de sécurité
    And le certificat est obtenu et stocké dans server.tls.acme.cache_dir
    And le WAF commence à écouter sur le port 443 avec ce certificat

  Scenario: Renouvellement automatique — 30 jours avant expiration
    Given le certificat de example.com expire dans 29 jours
    When le checker de renouvellement s'exécute (toutes les heures)
    Then le WAF initie le renouvellement automatiquement (≤ 30 jours avant expiration)
    And l'ancien certificat reste actif pendant le renouvellement
    And le nouveau certificat est activé atomiquement sans interruption

  Scenario: Rotation de certificat sans interruption de service
    Given un nouveau certificat vient d'être obtenu
    When le WAF active le nouveau certificat
    Then les connexions TLS existantes continuent avec l'ancien certificat
    And les nouvelles connexions utilisent le nouveau certificat
    And aucune connexion n'est interrompue

  Scenario: Challenge ACME HTTP-01 bypass sécurité WAF
    Given le WAF est en train de renouveler son certificat
    When Let's Encrypt fait une requête GET "/.well-known/acme-challenge/<token>"
    Then la requête bypass tous les middlewares (whitelist, challenge, rate limit)
    And la réponse ACME correcte est retournée
    And le certificat est obtenu avec succès

  Scenario: Alerte certificat expirant dans moins de 7 jours
    Given le certificat expire dans 5 jours
    And le renouvellement automatique a échoué (Let's Encrypt indisponible)
    When le checker s'exécute
    Then un webhook d'alerte "tls_cert_expiring" est envoyé avec severity="critical"
    And la métrique waf_tls_cert_expiry_seconds{domain="example.com"} est mise à jour
    And le WAF continue de fonctionner avec le certificat existant (même si expirant)

  Scenario: Certificats statiques (mode sans ACME)
    Given server.tls.acme.enabled = false
    And server.tls.cert_file = "/etc/ssl/waf/cert.pem"
    And server.tls.key_file = "/etc/ssl/waf/key.pem"
    When le WAF démarre
    Then il charge les certificats depuis les fichiers configurés
    And aucune requête ACME n'est effectuée

  Scenario: Hot-reload des certificats statiques (SIGHUP)
    Given les fichiers cert.pem et key.pem ont été mis à jour manuellement
    When le WAF reçoit SIGHUP
    Then le nouveau certificat est chargé sans redémarrage
    And les nouvelles connexions TLS utilisent le nouveau certificat

  Scenario: TLS 1.2 et 1.3 supportés, TLS 1.0/1.1 refusés
    Given la configuration TLS par défaut
    When un client tente de se connecter en TLS 1.0
    Then la connexion est refusée (version non supportée)
    When un client se connecte en TLS 1.3
    Then la connexion est établie normalement

  Scenario: Cipher suites configurables
    Given server.tls.min_version = "1.2"
    And server.tls.cipher_suites sont spécifiés (liste explicite)
    When un client propose un cipher suite non dans la liste
    Then la connexion TLS est refusée (handshake failure)

  Scenario: Métrique d'expiration des certificats
    When GET /waf/metrics
    Then la métrique waf_tls_cert_expiry_seconds{domain} est présente
    And indique le nombre de secondes avant expiration du certificat courant
