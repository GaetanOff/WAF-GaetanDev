---
status: proposed
date: 2026-09-01
deciders: GaetanDev
relates-to: requirements.md (FR-01, FR-06 v2.2.0), requirements-ops.md (FR-33 — TLS par domaine), features/js-challenge.feature, features/per-domain-tls.feature, ADR-017
---

# ADR-020 — Confiance accordée à l'en-tête `Host` pour le routage et la politique par domaine

> **Statut : proposed.** Les deux questions posées ici ont des réponses qui
> peuvent rejeter du trafic aujourd'hui accepté. Elles relèvent de l'opérateur.

## Context

L'en-tête `Host` est fourni par le client. Le WAF s'en sert pour deux choses :

1. **Router** vers l'upstream — `internal/proxy.resolveUpstream(r.Host)`, avec
   repli sur `upstream.address` si aucune entrée `domains[]` ne correspond.
2. **Choisir la politique de sécurité par domaine** — `domains[].challenge_enabled`
   (FR-06, T13.1), la liaison du cookie et du nonce de challenge à l'hôte
   émetteur, le comptage de pression par domaine du mode sous attaque (FR-39).

Les deux usages suivent `Host` de façon cohérente, ce qui limite l'escalade : un
client qui prétend être `api.example.com` obtient la politique **et** l'upstream
de `api.example.com`. Deux zones d'ombre subsistent néanmoins.

### Zone 1 — Hôte non listé : repli sur le défaut, y compris pour la politique

Un `Host` qui ne correspond à aucune entrée `domains[]` est routé vers
`upstream.address` et hérite de la politique **globale**. C'est le comportement
documenté et testé (`TestRoutesAppliesPerDomainChallengeOverride`, cas
`autre.test`).

Il devient un contournement dans une configuration pourtant banale :

```yaml
challenge:
  enabled: false            # global éteint
upstream:
  address: http://10.0.0.1  # même origine que boxaria.fr
domains:
  - host: boxaria.fr
    upstream: http://10.0.0.1
    challenge_enabled: true # durci pour ce domaine
```

Une requête `Host: peu-importe.test` atteint `10.0.0.1` — la même origine que
`boxaria.fr` — **sans challenge**. Le durcissement par domaine est contourné par
un en-tête, sans que l'attaquant ait besoin de connaître quoi que ce soit d'autre
que l'IP du WAF.

Le repli est utile (catch-all, health checks, accès par IP) ; le problème est
qu'il s'applique aussi à la **politique**, pas seulement au routage.

### Zone 2 — Aucune liaison entre le SNI et le `Host`

Avec la terminaison TLS par domaine (FR-33, ADR-017), le certificat est
sélectionné sur le **SNI** du `ClientHello` (`internal/tlsmgr`), tandis que le
routage et la politique suivent le **`Host` HTTP**. Rien ne vérifie que les deux
concordent : un client peut négocier `a.example.com` et envoyer
`Host: b.example.com`.

L'impact direct est faible — la politique et le routage suivent tous deux `Host`,
donc le client obtient un ensemble cohérent. Mais la conséquence est que **le
certificat présenté ne dit rien du domaine effectivement servi**, ce qui invalide
tout raisonnement de sécurité qui s'appuierait sur le SNI, et brouille la
corrélation dans les journaux et les métriques par domaine.

À noter : `redirectToHTTPS` valide déjà le `Host` entrant contre les domaines
configurés et répond `400` sinon — la garde existe donc pour le redirecteur, mais
pas pour le listener principal.

## Options Evaluees

### Zone 1 — hôte non listé

#### Option 1A — Statu quo, documenter

- **+** Aucun risque. Le repli reste prévisible.
- **-** Le durcissement par domaine reste contournable dans une configuration
  courante, et rien dans la configuration ne le signale à l'opérateur.

#### Option 1B — Politique la plus stricte pour un hôte non listé

Un `Host` non listé hérite non pas du global mais du **maximum de sévérité** des
entrées `domains[]` (challenge activé si au moins un domaine l'active, etc.).

- **+** Ferme la Zone 1 sans nouvelle clé de configuration.
- **-** Surprenant : un opérateur qui durcit un seul domaine durcit implicitement
  le catch-all. Peut casser un accès par IP ou une sonde.

#### Option 1C — `server.strict_host` opt-in : `400` sur un `Host` non listé

Aligne le listener principal sur ce que `redirectToHTTPS` fait déjà.

- **+** Explicite, prévisible, et ferme la Zone 1 net. Réutilise une logique et
  un précédent déjà présents dans le code.
- **+** L'option la plus simple à raisonner : soit l'hôte est déclaré, soit il
  n'est pas servi.
- **-** Opt-in obligatoire : activé par défaut, casse tout déploiement à upstream
  unique sans `domains[]`, l'accès par IP et les health checks externes. Demande
  une exemption pour `/waf/health`.

#### Option 1D — Séparer routage et politique

Le repli reste pour le **routage** ; la **politique** d'un hôte non listé devient
un réglage explicite (`domains_default_policy: inherit | strict`).

- **+** Traite la cause : c'est bien la confusion routage/politique qui crée le
  trou.
- **-** Nouvelle notion dans la configuration, et un troisième chemin à tester
  pour chaque contrôle par domaine.

### Zone 2 — liaison SNI ↔ `Host`

#### Option 2A — Statu quo, documenter

- **+** Aucun risque. L'impact direct est faible.
- **-** Laisse un écart silencieux entre certificat présenté et domaine servi.

#### Option 2B — Rejeter le désaccord SNI ≠ `Host` (`421` ou `400`)

- **+** Rétablit la liaison, et rend la corrélation par domaine fiable dans les
  journaux. `421 Misdirected Request` est la réponse prévue par HTTP/2 pour ce cas.
- **-** Casse la réutilisation de connexion HTTP/2 entre domaines partageant un
  certificat (comportement légitime et courant), les clients sans SNI, et le
  trafic en HTTP clair. Doit rester opt-in.

## Decision

**À prendre.** Avis de l'auteur de l'audit, à titre de recommandation :

- **Zone 1 : 1C en opt-in** (`server.strict_host`, défaut `false`), parce qu'elle
  réutilise un précédent déjà validé dans le code et qu'elle est la plus facile à
  raisonner pour un opérateur. 1D est plus juste conceptuellement mais coûte une
  notion de configuration supplémentaire pour un gain identique sur ce vecteur.
- **Zone 2 : 2A pour l'instant.** L'impact direct est faible et 2B casse des
  usages HTTP/2 légitimes. À revoir si une décision de sécurité vient un jour
  dépendre du SNI.

Rien n'est implémenté à ce jour, et **aucun comportement n'a été modifié** par la
passe d'audit sur ce sujet : la seule correction livrée concerne la condition `ip`
du moteur de règles (FR-17 v2.3.0, T14.3).

## Consequences

- Tant que la Zone 1 est ouverte, une configuration qui durcit un domaine tout en
  laissant `upstream.address` pointer sur la même origine DOIT être considérée
  comme non durcie. À documenter dans `CONFIG.md` à côté de
  `domains[].challenge_enabled`, où l'opérateur la lira.
- 1C, si retenue, exige que `/waf/health` reste servi hors validation — sinon les
  sondes de conteneur tombent.
- 1C et le repli du routage sont indépendants : `strict_host` peut être activé
  sans toucher `resolveUpstream`.

## Spec References

- `specs/requirements.md` FR-01 (reverse proxy), FR-06 v2.2.0 (challenge par domaine)
- `specs/requirements-ops.md` FR-33 — terminaison TLS par domaine
- `specs/features/js-challenge.feature`, `specs/features/per-domain-tls.feature`
- `specs/decisions/ADR-017-per-domain-tls.md`
- `specs/validation.md` — audit des surfaces de confiance implicite
