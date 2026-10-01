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

## Amendement — défauts implémentés (2026-09-30)

Constat d'audit : les défauts de cet ADR (`x_frame_options: "SAMEORIGIN"`,
`permissions_policy` et `x_xss_protection` injectés, `x_waf_protected`, CSP
par domaine, remplacement de `Server`) n'ont jamais été ceux du code, de
`config.schema.json` ni de CONFIG.md, qui font foi pour l'opérateur.

- `X-Frame-Options` vaut `DENY` par défaut (plus strict que `SAMEORIGIN`) ;
  `security_headers.frame_options: "SAMEORIGIN"` rétablit l'iframe même origine.
- `Permissions-Policy` et `Content-Security-Policy` sont opt-in, globaux.
- HSTS est posé quel que soit le transport (TLS terminé par Cloudflare en amont).
- Différés : réglages par domaine, `X-XSS-Protection`, `X-WAF-Protected`,
  remplacement de `Server`, `sanitize_errors`, métrique
  `waf_security_headers_injected_total`. Les pages d'erreur brandées (FR-32,
  `maintenance.error_pages`) masquent déjà les corps d'erreur de l'upstream.
- Les clés réelles sont plates (`config.schema.json`, bloc `security_headers`) :
  `hsts_max_age`, `hsts_include_subdomains`, `frame_options`,
  `content_type_nosniff`, `referrer_policy`, `permissions_policy`, `csp`,
  `strip_headers`. Il n'existe ni sous-bloc `hsts:`, ni option `preload`, ni
  clés `strict_transport_security`, `x_frame_options`,
  `x_content_type_options` ou `content_security_policy` (amendé le 2026-10-01).

## Spec References

- [requirements-ops.md](../requirements-ops.md) FR-21, FR-22
- [features/security-headers.feature](../features/security-headers.feature)
