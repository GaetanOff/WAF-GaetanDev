---
status: accepted
date: 2026-11-09
deciders: GaetanDev
relates-to: requirements-ops.md (FR-41), requirements.md (FR-06, FR-07), schemas/config.schema.json (DomainConfig), features/non-browser-paths.feature, ADR-022
---

# ADR-023 — Exemption anti-bot par chemin, par domaine

## Context

`POST /v1/siteverify` de `captcha.gaetandev.fr` est appelé serveur à serveur
par les backends des sites intégrateurs (Node `fetch`/undici, Guzzle, curl,
python-requests…), depuis des IP et avec des User-Agent arbitraires.
`challenge_enabled: false` ne lève que le challenge JS : l'anti-bot (FR-07,
`internal/middleware/antibot/rules.go`) continue de pénaliser, sur le score
par IP et domaine (initial 50, `block_threshold` 10, `score_ttl` 1 h) :

| Raison | Delta | Déclencheur |
|---|---|---|
| `missing_user_agent` | −20 | User-Agent vide |
| `suspicious_user_agent` | −15 | `python-requests`, `curl/`, `wget/`, `go-http-client` |
| `missing_browser_header` | −5 / en-tête | `Accept-Language` et/ou `Accept-Encoding` absents |

Un backend intégrateur tombe sous le seuil en 3 à 10 appels et reçoit 403
pendant une heure, pour toute son IP sur ce domaine (audit du 2026-11-09,
point critique). Cloudflare exclut déjà `/v1/*` de ses propres contrôles ; le
WAF n'offre aucune option ciblant un chemin (`public_paths` a été retiré par
ADR-022, et c'était une exemption de challenge, pas d'anti-bot).

## Options Evaluees

### A — Ajouter les UA des clients HTTP à `whitelist_user_agents`

- **+** Aucun code.
- **−** Global à tous les domaines ; exempte aussi du challenge proactif
  partout : `User-Agent: node` contournerait le challenge des autres sites.
- **−** Ne couvre pas `missing_user_agent` ; la liste n'est jamais exhaustive.

### B — Whitelister les IP des intégrateurs

- **−** Contournement total (aucune protection) ; IP tierces inconnues et
  changeantes.

### C — Réintroduire `public_paths` (ADR-022)

- **−** Sémantique « jamais de challenge », qui ne résout pas le problème (le
  challenge est déjà désactivé) ; rouvre une clé retirée.

### D — `antibot_enabled: false` par domaine

- **+** Simple.
- **−** Retire aussi honeypot, UA d'automatisation et headless sur tout le
  domaine, pages HTML comprises.

### E — `domains[].non_browser_paths` limité aux trois signaux non-navigateur

- **+** Portée minimale : un domaine, des chemins, trois heuristiques qui ne
  prouvent que « pas un navigateur » — la même catégorie que l'exemption
  existante de `whitelist_user_agents` (`isNonBrowserSignal`), élargie ici à
  `missing_user_agent`.
- **+** Signaux déterministes (honeypot, automation, état `BLOCKED`) et
  défenses de volume (rate limit, anti-DDoS) intacts.
- **−** Une clé de plus dans `DomainConfig` ; validation stricte à maintenir.

## Decision

**Option E**, décision d'opérateur du 2026-11-09.

- `DomainConfig.non_browser_paths` : motif terminé par `/` = préfixe, sinon
  exact, sensible à la casse. Un chemin de requête non canonique (`.`, `..`,
  `//`) n'est jamais exempté : la comparaison porte sur `r.URL.Path` tel que
  reçu, et `/v1/../admin` ne doit pas hériter de l'exemption de `/v1/`.
- L'entrée `domains[]` est résolue comme pour le routage (première entrée
  correspondante, wildcard couvrant l'apex), **sans héritage** : une entrée
  exacte sans la clé ne prend pas la liste d'un wildcard placé après.
- L'exemption se décide dans `antibot.Middleware.Handler`, après
  `Rules.Evaluate` : `isNonBrowserSignal` (exemption de la whitelist UA) reste
  inchangé, un prédicat distinct y ajoute `missing_user_agent` pour FR-41
  seulement — la whitelist UA ne gagne pas cette raison.
- Le `pattern` de `config.schema.json` est écrit sans assertion avant
  (lookahead) : la version proposée en revue n'était pas compilable par le
  moteur RE2 de Go, ce qui rendait impossible le test de cohérence schéma ↔
  `config.Validate` exigé par FR-41.
- Métrique `waf_antibot_non_browser_exempt_total{domain}`, `domain` = `host`
  configuré de l'entrée.

## Consequences

- Ajout non cassant (MINEUR) : `config.schema.json` (propriété optionnelle,
  `additionalProperties: false` conservé), `requirements-ops.md` 3.17.0.
- ADR-022 n'est pas remis en cause : nouvelle clé, effectivement appliquée,
  sémantique distincte (anti-bot, pas challenge), refusée si mal formée.
- Un attaquant peut forger l'absence d'en-têtes navigateur sur `/v1/*` sans
  pénalité : accepté — ces signaux ne valent que −5 à −20 et se forgent déjà
  (n'importe quel client peut envoyer `Accept-Language`) ; le volume reste
  borné par le rate limiting et l'anti-DDoS, et l'abus métier par le service
  captcha lui-même (preuve de travail, scoring, limitation applicative).
- Déploiement : ajouter `non_browser_paths: ["/v1/"]` à l'entrée
  `captcha.gaetandev.fr`, puis lever les visiteurs déjà bloqués
  (`DELETE /waf/admin/visitors/{ip_hash}`) ou attendre `trust.score_ttl`.

## Spec References

- `specs/requirements-ops.md` FR-41
- `specs/schemas/config.schema.json` — `definitions.DomainConfig.non_browser_paths`
- `specs/features/non-browser-paths.feature`
- `specs/requirements.md` FR-06 (challenge par domaine), FR-07 (anti-bot)
- `specs/decisions/ADR-022-remove-inert-domain-overrides.md`
