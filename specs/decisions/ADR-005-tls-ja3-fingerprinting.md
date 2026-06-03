---
status: accepted
date: 2026-06-03
deciders: GaetanDev
---

# ADR-005 — TLS/JA3 Fingerprinting

## Context

JA3 est un hash MD5 des paramètres du ClientHello TLS (version, cipher suites, extensions, courbes elliptiques, formats de points). Il est quasi-unique par couple (OS, bibliothèque TLS) et très difficile à modifier pour un attaquant — contrairement au User-Agent ou à l'IP. C'est l'une des méthodes anti-bot les plus robustes disponibles.

**Problème** : le WAF est derrière Cloudflare, qui termine le TLS. Le WAF reçoit donc du HTTP clair, pas du TLS.

## Options

### Option A — Cloudflare Bot Management header
Cloudflare expose `Cf-Bot-Management-Ja3Hash` si le plan Bot Management est activé.

**Avantages** : zéro code TLS côté WAF, toujours disponible
**Inconvénients** : plan payant (> 200$/mois), dépendance Cloudflare

### Option B — TLS inspection directe au niveau WAF
Configurer le WAF pour terminer le TLS lui-même et capturer le ClientHello via `crypto/tls.Config.GetConfigForClient`.

**Avantages** : fonctionne sans Cloudflare, gratuit, contrôle total
**Inconvénients** : dans l'architecture cible (Cloudflare en front), TLS est terminé par CF → WAF reçoit HTTP
— Solution : utiliser ce mode uniquement quand le WAF est déployé en direct (sans Cloudflare en front)

### Option C — Mode hybride (retenu)
1. Si `cloudflare.trusted: true` ET header `Cf-Bot-Management-Ja3Hash` présent → utiliser la valeur
2. Si le WAF termine TLS lui-même (`server.tls` configuré) → calculer JA3 depuis le ClientHello
3. Sinon → JA3 non disponible, feature désactivée gracieusement

## Decision

**Option C — Mode hybride.**

Implémentation Go pour la capture du ClientHello :
```go
tlsConfig := &tls.Config{
    GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
        ja3 := computeJA3(hello)
        // Store in request context via custom net.Listener
        return nil, nil
    },
}
```

La propagation du JA3 dans le contexte HTTP nécessite un `net.Listener` personnalisé qui wrap la connexion et injecte le JA3 dans un contexte avant de passer à `http.Server`.

**JA3 computation :**
```
MD5( TLSVersion, Ciphers, Extensions, EllipticCurves, EllipticCurvePoints )
Chaque liste est triée selon RFC et concaténée avec "-", séparée par ","
```

**Bibliothèque de référence** : implémentation custom Go (pas de lib externe — évite les dépendances)

## JA3 Blacklist

Les JA3 hashes suivants sont connus pour des outils malveillants courants et inclus par défaut :
- `3b5074b1b5d032e5620f69f9159a1b97` — Mirai botnet
- `ab16e0fd5f7a6bb6a0a2da7d8e9e3a78` — Python requests (configurable selon contexte)

Liste extensible via `threat_intel.ja3_blacklist` en config.

## Conséquences

- Nouveau package `internal/tls/ja3.go` : calcul hash JA3 depuis `*tls.ClientHelloInfo`
- Nouveau package `internal/tls/listener.go` : custom listener avec injection JA3 dans contexte
- `internal/middleware/cloudflare/middleware.go` : extraction `Cf-Bot-Management-Ja3Hash`
- `VisitorProfile` étendu avec champ `ja3_hash string`
- Feature désactivée proprement si ni CF header ni TLS direct disponible

## Spec References

- [requirements-advanced.md](../requirements-advanced.md) FR-11
- [ADR-004](ADR-004-fingerprinting.md) — Fingerprinting navigateur (complémentaire)
