---
status: accepted
date: 2026-06-03
deciders: GaetanDev
---

# ADR-011 — Stratégie Security Headers

## Context

Un WAF positionné devant une application a la responsabilité d'injecter des security headers de sécurité HTTP que l'application elle-même n'a pas forcément configurés. Ces headers protègent les navigateurs des utilisateurs contre des attaques côté client (clickjacking, XSS, MIME sniffing, etc.).

## Problème : Conflicts avec l'upstream

L'upstream peut déjà envoyer ces headers (correctement ou incorrectement). Le WAF ne doit pas créer de duplicates ou écraser une politique plus restrictive définie par l'application.

**Règle de priorité retenue** : l'upstream a la priorité. Si l'upstream envoie déjà un header, le WAF ne l'injecte pas.

```go
func (m *SecurityHeadersMiddleware) injectIfAbsent(w http.ResponseWriter, key, value string) {
    if w.Header().Get(key) == "" {
        w.Header().Set(key, value)
    }
}
```

## Content-Security-Policy — Cas Particulier

CSP est très spécifique à chaque application (listes de domaines autorisés, nonces, etc.). Une CSP trop restrictive cassera le site. Comportement retenu :
- CSP **non injectée par défaut** (trop de risque de casser l'app)
- Configurable par domaine avec une valeur explicite
- Si l'upstream envoie CSP → WAF ne touche pas

## Headers injectés par défaut

```yaml
security_headers:
  enabled: true
  strict_transport_security: "max-age=31536000; includeSubDomains"
  x_frame_options: "SAMEORIGIN"
  x_content_type_options: "nosniff"
  referrer_policy: "strict-origin-when-cross-origin"
  permissions_policy: "geolocation=(), microphone=(), camera=(), payment=()"
  x_xss_protection: "1; mode=block"  # legacy browsers
  content_security_policy: ""  # vide = non injecté
  x_waf_protected: "GaetanDev.fr/1.0"
```

## HSTS — Précaution

`includeSubDomains` peut casser des sous-domaines HTTP légitimes. Configurable séparément :
```yaml
hsts:
  max_age: 31536000
  include_subdomains: true  # désactiver si sous-domaines HTTP existent
  preload: false  # ne pas préloader par défaut (irréversible)
```

## Response Sanitization (inclus ici par cohérence)

Les headers qui révèlent l'infrastructure sont supprimés côté WAF en modifiant la réponse upstream avant de la transmettre au client.

Implémentation : `http.ResponseWriter` wrapper qui intercepte `WriteHeader()` et nettoie les headers avant d'appeler le `ResponseWriter` original.

```go
type sanitizingResponseWriter struct {
    http.ResponseWriter
    headersToRemove []string
    headersToReplace map[string]string
}

func (w *sanitizingResponseWriter) WriteHeader(code int) {
    for _, h := range w.headersToRemove {
        w.Header().Del(h)
    }
    for k, v := range w.headersToReplace {
        if w.Header().Get(k) != "" {
            w.Header().Set(k, v)
        }
    }
    w.ResponseWriter.WriteHeader(code)
}
```

**Headers supprimés par défaut** :
- `Server`
- `X-Powered-By`
- `X-Generator`
- `X-AspNet-Version`
- `X-AspNetMvc-Version`
- `X-Drupal-Cache`
- `X-Varnish`
- `Via` (révèle la chaîne de proxy)

`Server` peut être remplacé par une valeur custom : `Server: WAF/1.0` (configurable).

## Conséquences

- `internal/middleware/securityheaders/middleware.go` : injection headers + sanitisation
- Le middleware s'applique **après** la réponse de l'upstream (ResponseWriter wrapper)
- Les headers sont injectés une seule fois même si le handler upstream appelle WriteHeader plusieurs fois
- Config : bloc `security_headers` dans config.schema.json (à étendre)
- Métriques : `waf_security_headers_injected_total{header}` (pour debug)

## Spec References

- [requirements-ops.md](../requirements-ops.md) FR-21, FR-22
- [features/security-headers.feature](../features/security-headers.feature)
