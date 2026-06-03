Feature: Protection Adaptative (PoW Difficulty + Mode Dégradé)
  En tant que WAF,
  Je veux adapter automatiquement l'intensité de la protection en temps réel
  Afin d'augmenter le coût des attaques sans impacter les visiteurs légitimes en temps normal.

  Background:
    Given le WAF est configuré avec:
      | challenge.pow_difficulty     | 16 |
      | challenge.pow_max_difficulty | 24 |
      | adaptive.enabled             | true |
      | adaptive.decay_tau_seconds   | 300 |

  Scenario: Trafic normal — difficulté baseline
    Given le trafic courant est à 95% du trafic baseline
    When un nouveau visiteur est challengé
    Then la difficulté du challenge est 16 bits (baseline)
    And le message de la page est "Checking your browser…"

  Scenario: Trafic élevé — difficulté augmentée +2 bits
    Given le trafic courant est à 130% du trafic baseline (niveau Elevated)
    When un nouveau visiteur est challengé
    Then la difficulté du challenge est 18 bits (16 + 2)
    And la page affiche "Performing security verification…"

  Scenario: Attaque active — difficulté critique +8 bits
    Given le trafic courant est à 250% du trafic baseline (niveau Critical)
    When un nouveau visiteur est challengé
    Then la difficulté du challenge est 24 bits (16 + 8, plafonnée au max)
    And la page affiche "Enhanced security check in progress…"

  Scenario: Difficulté encodée dans le token anti-rétrogradation
    Given la difficulté courante est 22 bits (attaque active)
    When un attaquant soumet un challenge avec nonce calculé pour difficulté 16 bits
    Then le WAF détecte que la difficulté du token (22) ne correspond pas au PoW soumis
    And le challenge est rejeté avec HTTP 400 et {"error": "difficulty_mismatch"}
    And le score est décrémenté de 20

  Scenario: Retour à la normale après attaque — décroissance exponentielle
    Given la difficulté était à 24 bits (attaque stoppée il y a 1 minute)
    When 1 minute s'écoule après la fin de l'attaque
    Then la difficulté effective est approximativement 24 × e^(-60/300) ≈ 20 bits
    And la difficulté continue de baisser vers 16 bits au fil du temps

  Scenario: Retour complet à la normale (5 constantes de temps = 1500s)
    Given l'attaque s'est arrêtée il y a 25 minutes
    When la décroissance exponentielle s'est appliquée sur 1500s (5τ)
    Then la difficulté est revenue à 16 bits (baseline, < 1% d'écart)

  Scenario: Métrique de difficulté exposée
    When GET /waf/metrics
    Then la réponse contient la métrique "waf_challenge_pow_difficulty 18"
    And la métrique "waf_attack_intensity_indicator 1.30" (130%)

  Scenario: Baseline calculée sur EMA 24h
    Given le WAF a fonctionné pendant 24 heures avec un trafic moyen de 1000 req/s
    When le trafic monte à 1200 req/s
    Then l'AII est 120% et le niveau est "Elevated"
    And la difficulté augmente de +2 bits

  Scenario: Premier démarrage sans baseline — fallback
    Given le WAF vient de démarrer (pas de baseline historique)
    When le trafic courant est 2× le rate_limit.requests_per_second
    Then l'AII utilise le double de requests_per_second comme proxy de baseline
    And la protection adaptative fonctionne normalement

  Scenario: Désactivation de l'adaptation — difficulté fixe
    Given adaptive.enabled = false
    When n'importe quel niveau de trafic est observé
    Then la difficulté reste toujours à challenge.pow_difficulty (valeur config fixe)
