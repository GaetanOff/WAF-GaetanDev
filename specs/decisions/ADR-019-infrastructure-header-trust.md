---
status: proposed
date: 2026-09-01
deciders: GaetanDev
relates-to: requirements.md (FR-02), requirements-advanced.md (FR-11, FR-16, FR-17 v2.3.0), requirements-ops.md (FR-30 v3.2.1), features/geo-rules.feature, features/tls-fingerprinting.feature, ADR-005
---

# ADR-019 — Frontière de confiance des en-têtes d'infrastructure (`CF-*`, `ja3_header`)

> **Statut : proposed.** Cet ADR expose un constat et des options. La décision
> appartient à l'opérateur : chaque option a un coût de déploiement réel, et
> l'option D en particulier rejetterait du trafic aujourd'hui accepté.

## Context

L'audit des surfaces de confiance implicite (tâche ouverte de T14.1) a établi que
le WAF prend des décisions de sécurité sur des en-têtes **d'infrastructure** —
posés par un intermédiaire, jamais par le client — sans vérifier qu'ils viennent
bien de cet intermédiaire.

Trois lectures concernées :

| Lecture | Fichier | Décision pilotée |
|---|---|---|
| `CF-IPCountry` | `internal/geo/geo.go` | Blocage / challenge géographique (FR-16) |
| `CF-IPCountry` | `internal/rules/rules.go`, champ `country` | Toute action de règle (FR-17) |
| `tls_fingerprint.ja3_header`, défaut `Cf-Bot-Management-Ja3Hash` | `internal/tlsfp/middleware.go` | Blacklist JA3, trigger déterministe (FR-11) |

`internal/middleware/cloudflare` valide **uniquement** `CF-Connecting-IP`, et
uniquement quand `cloudflare.trusted` est vrai : si l'en-tête est présent alors
que la connexion ne vient pas d'une plage Cloudflare, la requête reçoit un `400`.
Tous les **autres** `CF-*` traversent sans contrôle. Et quand `cloudflare.trusted`
est faux, le middleware n'est pas monté du tout.

Conséquences constatées :

1. **Forge.** Un client qui atteint le WAF sans passer par Cloudflare — IP
   d'origine découverte, ou `cloudflare.trusted: false` — envoie
   `CF-IPCountry: FR` et sort d'un `blocked_countries: ["RU"]`, ou envoie un
   `Cf-Bot-Management-Ja3Hash` bénin et sort de la blacklist JA3. Aucun `400`
   n'est levé : ce contrôle ne regarde que `CF-Connecting-IP`.
2. **Omission, plus grave que la forge.** Ces trois lectures **dégradent
   gracieusement** quand l'en-tête est absent : `geo.go` laisse passer, `tlsfp`
   n'analyse rien. Le même attaquant obtient donc le même résultat en
   **omettant** l'en-tête. Autrement dit, FR-16 et la blacklist JA3 n'offrent
   aucune garantie dès qu'un client peut joindre le WAF hors Cloudflare — la
   forge n'en est qu'un cas particulier.
3. **`ja3_header` configurable hors namespace `CF-`.** Un déploiement derrière
   OpenResty peut poser `X-JA3-Fingerprint`. Rien ne distingue alors cet en-tête
   d'un en-tête client : il n'existe pas de liste de proxies de confiance dans la
   configuration.

Le nœud du problème n'est donc pas « ces en-têtes sont forgeables » mais **« le
WAF n'a aucune notion de : cette requête vient de mon intermédiaire de
confiance »**, alors que trois contrôles en dépendent.

## Options Evaluees

### Option A — Ne rien faire, documenter la limite

- **+** Zéro risque de régression. Cohérent avec FR-16, qui annonce déjà une
  dégradation gracieuse hors Cloudflare.
- **-** Laisse `geo_country_blocked` et la blacklist JA3 au rang de contrôles
  décoratifs dès que l'IP d'origine fuit — sans que l'opérateur le sache, puisque
  les métriques montrent des blocages qui « fonctionnent » sur le trafic honnête.

### Option B — Supprimer les `CF-*` non prouvés (assainissement, sans rejet)

Étendre le principe de FR-30 : si la connexion ne vient pas d'une plage
Cloudflare, ou si `cloudflare.trusted` est faux, supprimer tous les `CF-*` de la
requête entrante.

- **+** Aligne la forge sur l'omission : un `CF-IPCountry` forgé se comporte
  exactement comme un en-tête absent — chemin déjà spécifié et déjà testé. Aucun
  trafic nouvellement rejeté, aucune clé de configuration. Ferme au passage
  l'usurpation de `CF-Ray` dans les journaux.
- **+** Petit, testable, réversible.
- **-** Ne ferme **pas** l'omission (point 2 ci-dessus) : le contournement de
  FR-16 par accès direct reste ouvert. C'est une réduction de surface, pas une
  correction du contrôle.
- **-** Ne couvre pas un `ja3_header` hors namespace `CF-`.

### Option C — Liste de proxies de confiance (`trusted_proxies`)

Introduire `server.trusted_proxies: [<CIDR>]`, Cloudflare devenant une valeur
prédéfinie. Tout en-tête d'infrastructure — `CF-*`, `ja3_header`,
`X-Forwarded-*` — n'est honoré que si la connexion vient d'un de ces CIDR ;
sinon il est supprimé.

- **+** Traite la cause : le WAF gagne la notion d'intermédiaire de confiance, et
  elle devient explicite dans la configuration.
- **+** Couvre le déploiement OpenResty (`ja3_header` custom) que le projet
  documente déjà comme cible (`DEPLOYMENT.md`, bascule prod).
- **-** Nouvelle clé de configuration, nouvelle validation, migration : un
  déploiement en `cloudflare.trusted: true` doit être traduit. Risque de
  fail-closed si la liste est incomplète.
- **-** Ne ferme toujours pas l'omission par accès direct.

### Option D — Rejeter les connexions hors intermédiaire de confiance

En complément de B ou C : quand un intermédiaire de confiance est configuré,
répondre `403` à toute connexion qui n'en vient pas, hors `/waf/health`.

- **+** **Seule** option qui ferme l'omission, donc la seule qui rend FR-16 et la
  blacklist JA3 réellement contraignants. Rend aussi FR-19 redondant pour ce
  vecteur.
- **-** Change la politique d'accès du WAF. Casse les health checks externes, les
  sondes de monitoring, l'accès de secours par IP, et tout déploiement où le WAF
  est joignable directement à dessein. Doit être opt-in.
- **-** Demande une liste d'exemptions (chemins, CIDR d'administration), donc sa
  propre spec.

## Decision

**À prendre.** Avis de l'auteur de l'audit, à titre de recommandation :

- **B maintenant** : gain net, coût nul, aucune décision de politique à trancher.
  Aligne la forge sur un chemin déjà spécifié et testé.
- **C ensuite**, comme feature à part entière avec sa spec et sa migration — elle
  est de toute façon nécessaire pour la bascule OpenResty déjà planifiée.
- **D en opt-in seulement**, et pas avant C : sans liste de proxies de confiance
  explicite, un rejet par défaut est un fail-closed sur du trafic légitime.

Aucune de ces options n'est implémentée à ce jour. Ce qui **a** été corrigé dans
la même passe d'audit relève d'un autre registre et n'attendait aucune décision :
la condition `ip` du moteur de règles lisait `X-Real-IP`, un en-tête **client** —
corrigé en FR-17 v2.3.0, cf. T14.3.

## Consequences

- Tant qu'aucune option n'est retenue, `blocked_countries`, `allowed_countries` et
  `ja3_blacklist` DOIVENT être considérés comme des contrôles de **réduction de
  bruit**, pas comme des frontières de sécurité. À refléter dans `CONFIG.md` au
  moment de la décision.
- L'option B, si retenue, se pose naturellement à côté de `ingress.Middleware` :
  même position dans la chaîne, même logique de préfixe, mais conditionnée à
  l'origine de la connexion — donc dans `internal/middleware/cloudflare`, qui
  connaît déjà les plages.
- L'option C rendrait `cloudflare.trusted` redondant et ouvrirait sa dépréciation.

## Spec References

- `specs/requirements.md` FR-02 — extraction IP Cloudflare
- `specs/requirements-advanced.md` FR-11 (JA3), FR-16 (géo), FR-17 (règles, v2.3.0)
- `specs/requirements-ops.md` FR-30 v3.2.1 — assainissement d'ingress, le précédent
- `specs/features/geo-rules.feature`, `specs/features/tls-fingerprinting.feature`
- `specs/decisions/ADR-005-tls-ja3-fingerprinting.md`
- `specs/validation.md` — audit des surfaces de confiance implicite
