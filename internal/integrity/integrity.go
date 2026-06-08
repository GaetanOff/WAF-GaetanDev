// Package integrity analyse l'intégrité des requêtes HTTP (FR-18) : obfuscation
// de path, octets nuls, longueurs excessives, patterns d'injection. Il publie
// une contribution de la famille `integrity` au moteur de risque et applique une
// limite de taille de body.
package integrity

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gaetandev/waf/internal/config"
)

const (
	headerRiskIntegrity = "X-WAF-Risk-integrity"
	headerReason        = "X-WAF-Reason"

	// Contributions de risque par type de détection (sommées, bornées à 100).
	contribTraversal = 60
	contribNullByte  = 60
	contribInjection = 40
	contribTooLong   = 25
)

// Reasons exposés pour l'observabilité.
const (
	ReasonPathTraversal = "path_traversal"
	ReasonNullByte      = "null_byte"
	ReasonInjection     = "injection_pattern"
	ReasonExcessiveSize = "excessive_length"
	ReasonBodyTooLarge  = "body_too_large"
)

// Analyzer évalue l'intégrité d'une requête sans la bloquer (sauf body trop
// volumineux). Les détections contribuent au score de risque (FR-18).
type Analyzer struct {
	enabled        bool
	maxBodyBytes   int64
	maxPathLength  int
	maxQueryLength int
}

// Result agrège la contribution de risque et la raison principale.
type Result struct {
	Contribution int
	Reason       string
}

func NewAnalyzer(cfg config.Config) Analyzer {
	return Analyzer{
		enabled:        cfg.Integrity.Enabled,
		maxBodyBytes:   cfg.Integrity.MaxBodyBytes,
		maxPathLength:  cfg.Integrity.MaxPathLength,
		maxQueryLength: cfg.Integrity.MaxQueryLength,
	}
}

// Evaluate inspecte path + query string et retourne la contribution cumulée.
func (a Analyzer) Evaluate(r *http.Request) Result {
	rawPath := r.URL.EscapedPath()
	rawQuery := r.URL.RawQuery
	raw := strings.ToLower(rawPath + "?" + rawQuery)
	// Forme décodée (%xx + `+`→espace) pour défaire l'obfuscation simple.
	decoded := raw
	if u, err := url.QueryUnescape(rawPath + "?" + rawQuery); err == nil {
		decoded = strings.ToLower(u)
	}

	contribution := 0
	reason := ""
	add := func(delta int, why string) {
		contribution += delta
		if reason == "" {
			reason = why
		}
	}

	if containsNullByte(raw) || containsNullByte(decoded) {
		add(contribNullByte, ReasonNullByte)
	}
	if containsTraversal(raw) || containsTraversal(decoded) {
		add(contribTraversal, ReasonPathTraversal)
	}
	if containsInjection(raw) || containsInjection(decoded) {
		add(contribInjection, ReasonInjection)
	}
	if len(rawPath) > a.maxPathLength || len(rawQuery) > a.maxQueryLength {
		add(contribTooLong, ReasonExcessiveSize)
	}

	if contribution > 100 {
		contribution = 100
	}
	return Result{Contribution: contribution, Reason: reason}
}

// Handler applique la limite de taille de body (413) puis publie la contribution
// `integrity` pour le moteur de risque. Il ne bloque jamais sur les détections
// d'obfuscation/injection (FR-18 : laisser l'app décider, le moteur arbitre).
func (a Analyzer) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.enabled || r.Header.Get("X-WAF-Action") == "PASS" {
			next.ServeHTTP(w, r)
			return
		}

		if a.maxBodyBytes > 0 {
			if r.ContentLength > a.maxBodyBytes {
				w.Header().Set(headerReason, ReasonBodyTooLarge)
				http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, a.maxBodyBytes)
		}

		if result := a.Evaluate(r); result.Contribution > 0 {
			r.Header.Set(headerRiskIntegrity, strconv.Itoa(result.Contribution))
			if r.Header.Get(headerReason) == "" {
				r.Header.Set(headerReason, result.Reason)
			}
		}

		next.ServeHTTP(w, r)
	})
}

func containsNullByte(value string) bool {
	return strings.Contains(value, "%00") || strings.ContainsRune(value, '\x00')
}

func containsTraversal(value string) bool {
	return containsAny(value,
		"../", "..\\",
		"%2e%2e", "..%2f", "..%5c",
		"%2e%2e%2f", "%2e%2e/",
	)
}

func containsInjection(value string) bool {
	return containsAny(value,
		// SQL
		"union select", "select ", " or 1=1", "' or '", "drop table", "; drop", "/*", "--",
		// Script / XSS
		"<script", "javascript:", "onerror=", "onload=",
	)
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
