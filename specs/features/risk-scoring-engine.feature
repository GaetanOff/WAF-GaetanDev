Feature: Moteur de Scoring de Risque & Décision graduée
  En tant que WAF,
  Je veux fusionner tous les signaux en une décision graduée et corroborée
  Afin d'être très efficace contre les bots/DDoS tout en minimisant les faux positifs.

  Background:
    Given le moteur de risque est actif avec le profil "balanced"
    And le BLOCK heuristique exige au moins 2 familles de signaux corroborantes
    And un CHALLENGE précède toujours un BLOCK pour les signaux non déterministes

  # --- Corroboration : cœur anti-faux-positif (FR-35) ---

  Scenario: Un signal heuristique isolé ne bloque jamais
    Given un visiteur dont seule la famille "reputation" dépasse son seuil (ASN datacenter)
    And aucune autre famille n'est au-dessus de son seuil
    When le moteur calcule la décision
    Then la décision est "CHALLENGE"
    And la décision n'est PAS "BLOCK"
    And la RiskAssessment indique corroborating_families = 1

  Scenario: Deux familles corroborantes autorisent le BLOCK
    Given un visiteur dont les familles "behavioral" et "fingerprint" dépassent leur seuil
    And la confiance est supérieure au seuil block_min_confidence
    When le moteur calcule la décision
    Then la décision est "BLOCK"
    And la RiskAssessment indique corroborating_families >= 2
    And decision_basis = "heuristic"

  Scenario: Risk score élevé mais confiance insuffisante → plafonné à CHALLENGE
    Given un visiteur avec un risk_score = 85 mais une confidence = 0.2 (peu de signaux)
    When le moteur calcule la décision
    Then la décision est plafonnée à "CHALLENGE"
    And la décision n'est PAS "BLOCK"

  # --- Signaux déterministes : exemptés de corroboration (FR-35) ---

  Scenario: Une IP en blacklist explicite bloque seule
    Given un visiteur dont l'IP est en blacklist explicite
    When le moteur calcule la décision
    Then la décision est "BLOCK"
    And decision_basis = "deterministic"
    And deterministic_trigger = "blacklist"

  Scenario: Le déclenchement d'un honeypot bloque seul et révoque le trust
    Given un visiteur bénéficiant d'un trust persistant
    When il suit un lien honeypot injecté
    Then la décision est "BLOCK"
    And deterministic_trigger = "honeypot"
    And le trust persistant du visiteur est révoqué

  Scenario: Réputation threat-intel critique bloque seule
    Given un visiteur dont le score AbuseIPDB est 92 (>= 80)
    When le moteur calcule la décision
    Then la décision est "BLOCK"
    And deterministic_trigger = "threat_intel_critical"

  # --- Bots vérifiés : anti-faux-positif crawlers (FR-36) ---

  Scenario: Googlebot vérifié par reverse-DNS est autorisé malgré l'ASN datacenter
    Given une requête avec user-agent "Googlebot"
    And le reverse-DNS de l'IP résout vers "crawl-66-249-66-1.googlebot.com"
    And la résolution directe de ce hostname re-contient l'IP source
    When le moteur calcule la décision
    Then la décision est "ALLOW"
    And verified_good_bot = "googlebot"
    And aucune décision heuristique ne peut bloquer ce visiteur

  Scenario: Crawler déclaré en attente de vérification n'est jamais challengé
    Given une requête avec user-agent "Googlebot"
    And la vérification reverse-DNS de l'IP n'est pas encore résolue (cache miss)
    When le moteur calcule la décision
    Then la décision est plafonnée à "OBSERVE"
    And la décision n'est PAS "CHALLENGE"
    And la décision n'est PAS "BLOCK"
    And une vérification reverse-DNS asynchrone est déclenchée

  Scenario: Faux Googlebot (UA spoofé sans reverse-DNS valide) est traité comme suspect
    Given une requête avec user-agent "Googlebot"
    And le reverse-DNS de l'IP ne correspond pas à un domaine Google
    When le moteur calcule la décision
    Then verified_good_bot est nul
    And la contribution de la famille "reputation" est augmentée

  # --- Crédits de preuve humaine & trust persistant (FR-37) ---

  Scenario: Un humain ayant réussi le challenge n'est pas re-challengé
    Given un visiteur avec un cookie de session valide (challenge réussi récemment)
    And son fingerprint et son JA3 sont stables
    When il envoie une nouvelle requête
    Then la décision est "ALLOW"
    And sticky_trust = true
    And la RiskAssessment inclut un facteur "human_credit" à contribution négative

  Scenario: Un crédit humain empêche un blocage heuristique
    Given un visiteur avec une preuve d'humanité forte (challenge réussi, fingerprint stable)
    And une famille heuristique dépasse son seuil
    When le moteur calcule la décision
    Then la décision n'est PAS "BLOCK"
    And la décision est au plus "CHALLENGE"

  # --- Échelle graduée & réversibilité (FR-34) ---

  Scenario Outline: Mapping (risk_score, confidence) vers le tier de mitigation
    Given un visiteur avec un risk_score = <score> et une confidence = <conf>
    When le moteur calcule la décision
    Then la décision est "<tier>"

    Examples:
      | score | conf | tier      |
      | 5     | 0.9  | ALLOW     |
      | 30    | 0.8  | OBSERVE   |
      | 50    | 0.8  | THROTTLE  |
      | 70    | 0.8  | CHALLENGE |
      | 90    | 0.9  | BLOCK     |

  Scenario: La mitigation est réversible — l'humain remonte dans l'échelle
    Given un visiteur classé "CHALLENGE" par heuristique
    When il réussit le challenge JS
    Then sa décision suivante est "ALLOW"
    And le compteur waf_challenge_pass_after_flag_total est incrémenté

  # --- Garde-fous faux positifs & mode shadow (FR-38) ---

  Scenario: Une règle en mode shadow est journalisée mais non appliquée
    Given une nouvelle règle durcissante déployée en mode shadow
    And cette règle classerait le visiteur en "BLOCK"
    When le moteur calcule la décision
    Then la requête n'est PAS bloquée
    And la RiskAssessment est journalisée avec shadow_mode = true

  Scenario: La boucle de feedback fait décroître le poids d'un faux positif probable
    Given un visiteur flaggé "CHALLENGE" par la famille "behavioral"
    When il réussit le challenge
    Then le poids de la famille "behavioral" décroît pour ce visiteur
    And un compteur de faux positif probable est incrémenté

  # --- Explicabilité (NFR-17) ---

  Scenario: Chaque décision produit une RiskAssessment explicable
    Given n'importe quelle requête traitée par le moteur
    When la décision est calculée
    Then une RiskAssessment conforme à risk-assessment.schema.json est produite
    And elle liste chaque facteur contributif (famille, signal, valeur, contribution, poids)
    And une forme condensée est incluse dans l'événement de sécurité loggé

  # --- Performance (NFR-16) ---

  Scenario: La décision synchrone respecte le budget de latence
    Given tous les signaux sont déjà calculés (caches chauds)
    When le moteur fusionne et décide
    Then aucune I/O bloquante n'est effectuée
    And la partie synchrone s'exécute en moins de 50 microsecondes
