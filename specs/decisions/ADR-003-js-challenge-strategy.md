---
status: accepted
date: 2026-06-03
deciders: GaetanDev
---

# ADR-003 — Stratégie du challenge JavaScript

## Context

Le WAF doit valider silencieusement qu'un visiteur exécute un vrai navigateur sans imposer de CAPTCHA. Deux approches principales existent : le proof-of-work (PoW) et le fingerprinting seul.

## Options Evaluées

### Option A — Proof-of-Work seul
Le navigateur calcule un hash (SHA-256) jusqu'à trouver un nonce qui satisfait une difficulté (N zéros en tête). Simple, vérifiable côté serveur, mais :
- Des bots avec GPU peuvent le résoudre plus vite qu'un humain
- N'apporte pas d'information sur le navigateur

### Option B — Fingerprinting seul
Collecte de signaux navigateur (canvas hash, WebGL, timezone, fonts, etc.). Problèmes :
- Difficulté de vérification côté serveur sans comparaison de base
- Contournable avec des bots headless qui émulent les fingerprints

### Option C — PoW + Fingerprinting + Timing (retenu)
Combinaison des deux approches avec une contrainte temporelle :
1. **Proof-of-Work** : SHA-256 avec difficulté adaptative (~ 500 ms à 2 s sur un CPU standard)
2. **Fingerprinting** : collecte de ≥8 signaux navigateur, hash SHA-256 résultant
3. **Timing** : le challenge doit être complété entre 500 ms et 10 000 ms
4. **Token HMAC** : le nonce est signé côté serveur avec TTL 30 s

## Decision

**Option C retenue** — PoW + Fingerprinting + Timing.

**Paramètres du proof-of-work :**
- Algorithme : SHA-256 (disponible nativement en JS via SubtleCrypto API)
- Difficulté : nonce tel que SHA-256(challenge_token + nonce) commence par `0000` (4 zéros hex = 16 bits)
- Difficulté ajustable via config : `challenge.pow_difficulty` (défaut: 16 bits)

**Signaux de fingerprinting collectés :**
- User-Agent string
- Timezone offset (en minutes)
- Langue navigateur (`navigator.language`)
- Résolution écran (`screen.width × screen.height × screen.colorDepth`)
- Nombre de cœurs CPU (`navigator.hardwareConcurrency`)
- Touch support (`navigator.maxTouchPoints`)
- Canvas fingerprint (dessin d'un texte + formes, hash du pixel buffer)
- WebGL renderer string (`gl.getParameter(gl.RENDERER)`)
- Plugins count (`navigator.plugins.length`)

**Hash final du fingerprint :** SHA-256 de la concaténation JSON des 9 signaux.

**Validation côté serveur :**
1. Vérifier la signature HMAC du token (rejeter si invalide)
2. Vérifier l'expiration du token (rejeter si > 30 s)
3. Vérifier que SHA-256(token + nonce) commence par les N bits requis
4. Vérifier `elapsed_ms` ∈ [500, 10000]
5. Enregistrer le fingerprint hash pour détection de cohérence future

**Implémentation JS côté client :**
- Utilise `SubtleCrypto.digest('SHA-256', ...)` (API native, pas de bibliothèque externe)
- Exécution asynchrone avec `async/await` pour ne pas bloquer le thread UI
- Chronomètre visuel sur la page

## Consequences

- `internal/middleware/challenge/nonce.go` : génération et vérification du token signé
- `internal/middleware/challenge/pow.go` : vérification du proof-of-work côté serveur
- `web/challenge.html` : JS embarqué inline (pas de dépendances CDN pour éviter la dépendance externe)
- La difficulté PoW est ajustable sans redémarrage (hot-reload config)
- Les fingerprints sont stockés hashés (privacy by design)

## Spec References

- [requirements.md](../requirements.md) FR-06 (Challenge JavaScript)
- [architecture.md](../architecture.md) — Séquence JS Challenge
