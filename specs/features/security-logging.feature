Feature: Journalisation des événements de sécurité et formats de sortie (FR-09)
  En tant qu'opérateur du WAF,
  Je veux choisir entre un flux JSON exploitable par un collecteur et un rendu console lisible
  Afin de pouvoir déboguer localement sans renoncer au contrat d'audit en production.

  Background:
    Given le WAF est configuré avec logging.level = "info"
    And logging.output = "stdout"

  Scenario: Format json (défaut) — contrat d'audit
    Given logging.format = "json"
    When le WAF bloque une requête de "203.0.113.20"
    Then une ligne JSON est écrite sur stdout
    And elle valide "security-event.schema.json"
    And elle contient timestamp, request_id, ip, domain, path, action, reason, trust_score
    And elle ne contient aucune séquence d'échappement ANSI

  Scenario: Format pretty — rendu console lisible
    Given logging.format = "pretty"
    And la sortie est un terminal
    When le WAF bloque une requête de "203.0.113.21"
    Then une ligne lisible par un humain est écrite sur stdout
    And elle porte l'action "BLOCK", l'IP, la méthode, le chemin et la raison
    And l'action est colorisée

  Scenario: Format pretty redirigé vers un fichier — aucune colorisation
    Given logging.format = "pretty"
    And la sortie est redirigée vers un fichier
    When le WAF journalise un événement
    Then la ligne écrite ne contient aucune séquence ANSI

  Scenario: NO_COLOR respecté
    Given logging.format = "pretty"
    And la variable d'environnement NO_COLOR est définie
    When le WAF journalise un événement vers un terminal
    Then la ligne écrite ne contient aucune séquence ANSI

  Scenario: Le format ne change rien au reste du contrat
    Given logging.format = "pretty"
    When le WAF journalise 1000 événements
    Then l'écriture reste asynchrone (le chemin de requête n'est pas bloqué, NFR-16)
    And le niveau configuré filtre les événements comme en format json
    And le compteur d'événements abandonnés reste exposé

  Scenario: Valeur de format inconnue rejetée au démarrage
    Given logging.format = "logfmt"
    When le WAF démarre
    Then le démarrage échoue avec une erreur de validation nommant "logging.format"
