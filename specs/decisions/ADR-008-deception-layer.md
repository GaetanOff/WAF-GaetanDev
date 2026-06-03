---
status: accepted
date: 2026-06-03
deciders: GaetanDev
---

# ADR-008 — Deception Layer (Tarpit + Honeypot Content)

## Context

Les solutions de sécurité traditionnelles bloquent les bots et les font passer à la cible suivante. La deception layer retourne cette logique : au lieu de bloquer, on consomme les ressources de l'attaquant, on pollue ses données, et on l'identifie de manière plus certaine.

## Tarpit

### Problème de goroutine exhaustion

Un tarpit naïf (HTTP `time.Sleep(60s)`) maintient une goroutine + une connexion TCP pendant toute la durée. Si 10 000 bots se connectent simultanément : 10 000 goroutines = 20 GB de stack = OOM.

### Solution retenue : Chunked slow response avec semaphore

```go
type TarpitWriter struct {
    w          http.ResponseWriter
    chunkSize  int           // bytes par chunk (défaut: 64)
    delay      time.Duration // délai entre chunks (défaut: 2s)
    maxChunks  int           // chunks max avant fermeture (défaut: 30 → 60s total)
}

func (t *TarpitWriter) Write() {
    // Acquire semaphore slot (max 500 concurrent tarpits)
    select {
    case tarpitSemaphore <- struct{}{}:
        defer func() { <-tarpitSemaphore }()
    default:
        // Semaphore full → fallback to 429
        http.Error(t.w, "", 429)
        return
    }
    
    for i := 0; i < t.maxChunks; i++ {
        t.w.Write(fakeChunk(i))
        t.w.(http.Flusher).Flush()
        time.Sleep(t.delay)
    }
}
```

Le semaphore garantit que jamais plus de 500 goroutines ne sont en attente tarpit.

### Contenu de la réponse tarpit

Une réponse HTML simulant un chargement infini :
- Status 200, Content-Type text/html
- Progressive rendering : envoi du `<head>`, puis des `<div>` fake un par un
- Donne l'impression au bot que la page charge vraiment

## Honeypot Content Injection

### Injection dans les réponses HTML

Le WAF intercepte les réponses `Content-Type: text/html` de l'upstream et injecte avant `</body>` :

```html
<!-- contenu invisible pour les humains -->
<div style="display:none;visibility:hidden;font-size:0;height:0;width:0;overflow:hidden">
  <a href="/waf-trap/newsletter-unsubscribe-abc123">unsubscribe</a>
  <a href="/waf-trap/contact-removed">contact@honeypot.invalid</a>
  <!-- email harvester bait -->
  <span>noreply-trap@honeypot.gaetandev.invalid</span>
</div>
```

Les URLs `/waf-trap/` sont des honeypots. Tout visiteur qui les suit :
1. Déclenche le middleware honeypot
2. Score = 0 immédiatement
3. IP journalisée avec action=HONEYPOT

**L'email fake** empoisonne les listes de scrapers d'email. Si l'adresse reçoit des emails, c'est la preuve qu'un harvester est passé.

### Considérations SEO

Les liens honeypot ont attribut `rel="nofollow"` et `x-robots-tag: noindex` pour éviter que Google les indexe. Les whitelistés Googlebot ne les voient pas (injection bypass si user-agent whitelisté).

### Rotation des liens honeypot

Les URLs honeypot DOIVENT être rotatives (basées sur un hash hebdomadaire) pour éviter que les bots apprennent à les éviter en dur.

## Conséquences

- `internal/deception/tarpit.go` : TarpitWriter + semaphore
- `internal/deception/injection.go` : HTML response modifier (injection avant `</body>`)
- `internal/deception/honeypot.go` : middleware de détection des visites honeypot
- L'injection HTML nécessite une lecture complète de la réponse upstream → légère augmentation de latence pour les réponses HTML (< 1 ms pour pages < 100 KB)
- Activation opt-in par domaine : `deception.enabled: true`
- Les bots tarpités consomment de la bande passante upstream (le chunk fake est local, pas proxifié → pas de coût upstream)

## Spec References

- [requirements-advanced.md](../requirements-advanced.md) FR-15
- [features/deception-layer.feature](../features/deception-layer.feature)
