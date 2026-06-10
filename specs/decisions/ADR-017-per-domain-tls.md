---
status: accepted
date: 2026-06-10
deciders: GaetanDev
relates-to: requirements-ops.md (FR-31, FR-33), features/per-domain-tls.feature
---

# ADR-017 — Terminaison TLS par domaine (sélection par SNI)

## Context

Aujourd'hui le WAF ne sait terminer le TLS que via **ACME / Let's Encrypt**
(`internal/acme/acme.go`, `autocert` avec `HostWhitelist`). Il n'existe **aucun
moyen de charger des certificats existants** : ni un cert global statique réel
(la feature `acme-tls.feature` le mentionne mais ce n'est pas implémenté), ni
un certificat distinct **par domaine**.

Or la cible de déploiement réelle est un reverse proxy (OpenResty) qui termine
déjà le TLS pour **~34 vhosts**, chacun avec son propre certificat sur disque
(`/var/www/.../ssl/cert.pem`). Pour intercaler le WAF et qu'il inspecte le L7,
**le WAF doit terminer le TLS** — donc présenter le bon certificat selon le
domaine demandé (SNI) à partir des certificats déjà émis.

C'est la seule contrainte technique bloquante : le reste de la bascule
(OpenResty repassé en HTTP interne, upstream du WAF → OpenResty, `set_real_ip_from`)
est mécanique et hors périmètre de cet ADR.

## Options Évaluées

### Option A — Charger les certificats existants, sélection par SNI

Le WAF lit, pour chaque entrée `domains[]`, un `cert_file` / `key_file` PEM et
construit un `tls.Config.GetCertificate` qui choisit le certificat selon le
`ServerName` du `ClientHello` (avec support des wildcards `*.example.com`).

- **+** Réutilise les 34 certificats déjà émis et automatisés en amont. Aucune
  dépendance à Let's Encrypt, **zéro risque de rate-limit ACME**.
- **+** Migration progressive domaine par domaine, rollback trivial.
- **+** Indépendant du mode Cloudflare (orange/gris) : pas de challenge à exposer.
- **-** Le renouvellement reste géré hors WAF (l'outil qui produit déjà les PEM) ;
  le WAF doit recharger les certs (hot-reload SIGHUP ou redéploiement).

### Option B — ACME / Let's Encrypt pour les 34 domaines

Étendre la `HostWhitelist` `autocert` existante à tous les domaines.

- **+** Réutilise le code existant, renouvellement automatique intégré.
- **-** Derrière Cloudflare (proxy orange), `TLS-ALPN-01` ne fonctionne pas et
  `HTTP-01` est fragile (le challenge doit traverser CF). Risque de **rate-limit
  Let's Encrypt** sur 34 domaines lors d'un premier démarrage / d'une reprise.
- **-** Remplace une chaîne de certs qui marche déjà par une dépendance externe
  fragile au moment de la bascule.

### Option C — WAF en HTTP seul + Cloudflare en mode « Flexible »

Le WAF n'écoute qu'en HTTP sur l'origine ; Cloudflare termine le TLS côté visiteur
et parle en clair à l'origine.

- **+** Le plus simple, aucun code TLS à ajouter au WAF.
- **-** Affaiblit le chiffrement CF → origine (trafic en clair sur le lien),
  régression de sécurité par rapport à l'existant (CF → origine en HTTPS).
- **-** Ne répond pas au besoin « ajouter le TLS par domaine » sur le WAF.

## Decision

**Option A retenue** : terminaison TLS sur le WAF avec **sélection du certificat
par SNI** à partir de certificats statiques **définis par domaine**.

- Un bloc global `server.tls` active la terminaison (`enabled`), l'écoute HTTPS
  (`listen`, défaut `:443`), le plancher de version (`min_version`, défaut `1.2`),
  les cipher suites, et la redirection HTTP→HTTPS (`redirect_http`).
- Chaque `domains[]` porte un sous-bloc `tls { cert_file, key_file }`. Le WAF
  charge ces paires au démarrage et présente le certificat dont le `host`
  (exact ou wildcard) correspond au SNI.
- Un certificat **par défaut** optionnel (`server.tls.cert_file` / `key_file`)
  est servi pour les SNI sans correspondance ; sans lui, un SNI inconnu provoque
  un **refus de handshake** (pas de certificat servi par défaut silencieusement).
- **Fail-fast** : un `cert_file`/`key_file` manquant, illisible ou dont la clé ne
  correspond pas au cert fait **échouer le démarrage** (on ne sert pas un vhost
  cassé).
- ACME (FR-31) reste disponible comme mécanisme **complémentaire** et n'est pas
  modifié par cet ADR ; les deux ne sont pas activés simultanément sur le même
  listener dans la première version.
- La métrique `waf_tls_cert_expiry_seconds{domain}` (déjà prévue FR-31) est
  alimentée pour chaque certificat chargé.

Le hot-reload des certificats (SIGHUP) est **souhaitable** mais hors de la
première tranche d'implémentation (renouvellement géré en amont + redéploiement
acceptable au départ).

## Consequences

- Nouveau requirement **FR-33** (`requirements-ops.md`) et feature
  `features/per-domain-tls.feature`.
- Schéma de config : ajout de `server.tls` et `domains[].tls`
  (`schemas/config.schema.json`).
- Package `internal/tlsmgr` (chargement des certs + `GetCertificate` SNI),
  câblé dans `cmd/waf/main.go` à côté du chemin ACME existant. **Implémenté en
  Slice 11.1** (vérifié par tests unitaires + smoke test handshake réel).
- Impact déploiement (hors code) : OpenResty bascule en HTTP interne, l'upstream
  par défaut du WAF pointe vers OpenResty, et `set_real_ip_from` fait confiance au
  WAF. À documenter dans `DEPLOYMENT.md` au moment de l'implémentation.
- Le mode Cloudflare (orange vs gris) reste une décision de déploiement
  indépendante ; l'option A fonctionne dans les deux cas.

## Spec References

- [requirements-ops.md](../requirements-ops.md) FR-31, FR-33
- [features/per-domain-tls.feature](../features/per-domain-tls.feature)
- [schemas/config.schema.json](../schemas/config.schema.json)
