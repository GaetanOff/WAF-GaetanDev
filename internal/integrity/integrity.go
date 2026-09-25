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
	"github.com/gaetandev/waf/internal/wafheader"
)

const (
	headerRiskIntegrity = wafheader.RiskIntegrity
	headerAction        = wafheader.Action
	headerReason        = wafheader.Reason

	// Contributions de risque par type de détection (sommées, bornées à 100).
	contribTraversal = 60
	contribNullByte  = 60
	contribInjection = 40
	contribTooLong   = 25

	// maxDecodePasses borne le décodage récursif : au-delà de trois couches
	// d'encodage, l'obfuscation elle-même est anormale, et la borne interdit
	// qu'une entrée construite fasse boucler le décodage.
	maxDecodePasses = 3
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
//
// Chaque motif est cherché dans toutes les couches de décodage (%xx et `+`),
// jusqu'à maxDecodePasses : un seul décodage laissait passer un
// `%25252e%25252e%25252f` triplement encodé. Les injections sont en plus
// cherchées sur une forme normalisée (blancs repliés, commentaires SQL retirés,
// blancs autour de `=` supprimés), sans quoi `union%0aselect` ou `onload =`
// échappaient aux motifs à espacement fixe.
func (a Analyzer) Evaluate(r *http.Request) Result {
	rawPath := r.URL.EscapedPath()
	rawQuery := r.URL.RawQuery
	layers := decodeLayers(rawPath + "?" + rawQuery)

	contribution := 0
	reason := ""
	add := func(delta int, why string) {
		contribution += delta
		if reason == "" {
			reason = why
		}
	}

	if anyLayer(layers, containsNullByte) {
		add(contribNullByte, ReasonNullByte)
	}
	if anyLayer(layers, containsTraversal) {
		add(contribTraversal, ReasonPathTraversal)
	}
	if anyLayer(layers, containsInjection) || anyLayer(layers, containsNormalizedInjection) {
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
		if !a.enabled || r.Header.Get(headerAction) == wafheader.ActionPass {
			next.ServeHTTP(w, r)
			return
		}

		if a.maxBodyBytes > 0 {
			if r.ContentLength > a.maxBodyBytes {
				// Sans action posée, le refus était journalisé et compté PASS.
				w.Header().Set(headerAction, wafheader.ActionBlock)
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

// decodeLayers retourne la valeur brute puis chacune de ses formes décodées,
// en minuscules, jusqu'à ce qu'un décodage ne change plus rien ou échoue.
func decodeLayers(value string) []string {
	layers := make([]string, 1, maxDecodePasses+1)
	layers[0] = strings.ToLower(value)
	current := value
	for range maxDecodePasses {
		decoded, err := url.QueryUnescape(current)
		if err != nil || decoded == current {
			break
		}
		layers = append(layers, strings.ToLower(decoded))
		current = decoded
	}
	return layers
}

func anyLayer(layers []string, match func(string) bool) bool {
	for _, layer := range layers {
		if match(layer) {
			return true
		}
	}
	return false
}

func containsNormalizedInjection(value string) bool {
	return containsInjection(normalizeForMatching(value))
}

// normalizeForMatching replie toute suite de blancs (espace, tabulation, saut
// de ligne, caractères de contrôle) en un espace, remplace un commentaire
// SQL /*…*/ par un espace et retire les blancs autour de `=`. Les motifs
// d'injection, écrits avec un espacement canonique, retrouvent ainsi
// `union\nselect`, `union/**/select` ou `onload =`.
func normalizeForMatching(value string) string {
	var normalized strings.Builder
	normalized.Grow(len(value))
	pendingSpace, afterEquals := false, false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '/' && i+1 < len(value) && value[i+1] == '*' {
			if end := strings.Index(value[i+2:], "*/"); end >= 0 {
				i += end + 3
				pendingSpace = true
				continue
			}
		}
		if c <= ' ' && c != 0 {
			pendingSpace = true
			continue
		}
		if c == '=' {
			normalized.WriteByte(c)
			pendingSpace, afterEquals = false, true
			continue
		}
		if pendingSpace && !afterEquals && normalized.Len() > 0 {
			normalized.WriteByte(' ')
		}
		normalized.WriteByte(c)
		pendingSpace, afterEquals = false, false
	}
	return normalized.String()
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

// containsInjection cherche des motifs d'injection caractérisés. Les mots-clés
// ou ponctuations isolés ("select ", "--", "/*") en étaient exclus : ils
// apparaissent dans des URL légitimes (slug "mon--article", flag "--verbose",
// recherche "select a size", glob "/files/*") qui recevaient +40 de risque.
// Le commentaire SQL n'est retenu que derrière une quote, là où il tronque une
// requête injectée.
func containsInjection(value string) bool {
	return containsAny(value,
		// SQL
		"union select", "union all select", " or 1=1", "' or '", "\" or \"", "' or 1",
		"drop table", "; drop ", "'--", "' --", "'#", "/**/", "information_schema",
		"xp_cmdshell", "waitfor delay",
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
