Feature: Protection Adaptative (PoW Difficulty)
  En tant que WAF,
  Je veux adapter automatiquement l'intensité de la protection en temps réel
  Afin d'augmenter le coût des attaques sans impacter les visiteurs légitimes en temps normal.

  # Contrat : challenge.pow_difficulty et bloc `adaptive` de config.schema.json
  # (enabled, max_difficulty, decay_tau), FR-14, ADR-010. L'AII (Attack
  # Intensity Indicator) est le débit des 10 dernières secondes rapporté à une
  # baseline EMA (α = 0,05, mise à jour à chaque difficulté calculée).
  # Les scénarios @deferred sont spécifiés mais NON implémentés (audit du
  # 2026-09-24, point 4.1) : ils ne sont pas un critère d'acceptation tant que
  # leur implémentation n'est pas planifiée (specs/tasks.md).

  Background:
    Given le WAF est configuré avec:
      | challenge.pow_difficulty | 16   |
      | adaptive.enabled         | true |
      | adaptive.max_difficulty  | 24   |
      | adaptive.decay_tau       | 5m   |

  Scenario: Trafic normal — difficulté baseline
    Given l'AII courant est de 95 %
    When un nouveau visiteur est challengé
    Then la difficulté du challenge est 16 bits (baseline)

  Scenario: Trafic élevé — difficulté augmentée de 4 bits
    Given l'AII courant est de 130 % (au-dessus de 110 %)
    When un nouveau visiteur est challengé
    Then la difficulté du challenge est 20 bits (16 + 4)

  Scenario: Attaque active — difficulté critique +8 bits
    Given l'AII courant est de 250 % (au-dessus de 200 %)
    When un nouveau visiteur est challengé
    Then la difficulté du challenge est 24 bits (16 + 8, plafonnée à adaptive.max_difficulty)

  Scenario: Pression anti-DDoS — plancher de difficulté immédiat
    Given la pression globale anti-DDoS passe à "high"
    When un nouveau visiteur est challengé
    Then la difficulté est au moins 22 bits (16 + 6)
    # elevated : +4, high : +6, critical : +8 (FR-08 v2).

  Scenario: Difficulté encodée dans le token anti-rétrogradation
    Given la difficulté courante est 22 bits, signée dans le token de challenge
    When un attaquant soumet un nonce calculé pour la difficulté de base (16 bits)
    Then le PoW est vérifié à la difficulté du token, pas à la difficulté courante
    And le challenge est rejeté avec HTTP 400 et {"error": "invalid_pow"}
    And le score est décrémenté de 20
    # Le serveur ne peut pas distinguer un nonce « calculé pour 16 bits » d'un
    # nonce faux : les deux sont un PoW invalide (public.openapi.yaml).

  Scenario: Retour à la normale après attaque — décroissance exponentielle
    Given la difficulté était à 24 bits (attaque stoppée)
    When 1 minute s'écoule après la fin de l'attaque
    Then les bits ajoutés valent 8 × e^(-60/300) ≈ 6,5 : la difficulté est 23 bits
    And la difficulté continue de baisser vers 16 bits au fil du temps

  Scenario: Retour complet à la normale (5 constantes de temps = 1500s)
    Given l'attaque s'est arrêtée il y a 25 minutes
    When la décroissance exponentielle s'est appliquée sur 1500s (5τ)
    Then la difficulté est revenue à 16 bits

  Scenario: Métrique de difficulté exposée
    Given la difficulté courante est 20 bits
    When GET /waf/metrics
    Then la réponse contient la métrique "waf_challenge_pow_difficulty 20"

  Scenario: Désactivation de l'adaptation — difficulté fixe
    Given adaptive.enabled = false
    When n'importe quel niveau de trafic est observé
    Then la difficulté reste toujours à challenge.pow_difficulty (valeur config fixe)

  @deferred
  Scenario: Message de la page adapté à la difficulté
    Given la difficulté courante est 24 bits (niveau critique)
    When un nouveau visiteur est challengé
    Then la page affiche "Enhanced security check in progress…"
    # La page affiche aujourd'hui « Checking your browser… » quelle que soit la difficulté.

  @deferred
  Scenario: Métrique d'intensité d'attaque exposée
    When GET /waf/metrics
    Then la réponse contient la métrique "waf_attack_intensity_indicator 1.30" (130%)

  @deferred
  Scenario: Baseline calculée sur EMA 24h
    Given le WAF a fonctionné pendant 24 heures avec un trafic moyen de 1000 req/s
    When le trafic monte à 1200 req/s
    Then l'AII est 120% et le niveau est "Elevated"
    # La baseline est aujourd'hui une EMA à α = 0,05 par calcul de difficulté,
    # sans horizon de 24 h.

  @deferred
  Scenario: Premier démarrage sans baseline — fallback
    Given le WAF vient de démarrer (pas de baseline historique)
    When le trafic courant est 2× le rate_limit.requests_per_second
    Then l'AII utilise le double de requests_per_second comme proxy de baseline
    # La baseline est aujourd'hui initialisée au premier débit observé.
