package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Codes ANSI utilisés par le rendu `pretty`. Volontairement réduits aux
// couleurs de base : ce sont les seules dont le rendu est prévisible sur un
// terminal Windows, un tmux et un terminal de CI.
const (
	ansiReset     = "\x1b[0m"
	ansiDim       = "\x1b[90m"
	ansiRed       = "\x1b[31m"
	ansiBrightRed = "\x1b[91m"
	ansiGreen     = "\x1b[32m"
	ansiYellow    = "\x1b[33m"
	ansiMagenta   = "\x1b[35m"
	ansiCyan      = "\x1b[36m"
)

// promotedKeys est l'ordre de lecture du rendu `pretty` : ce qu'un humain
// cherche d'abord (quoi, qui, où, pourquoi), le reste étant ajouté ensuite en
// `clé=valeur`. Cet ordre est propre au format console — le contrat d'audit,
// lui, est porté par le format json et security-event.schema.json (FR-09).
var promotedKeys = []string{
	"timestamp", "action", "ip", "method", "domain", "path",
	"upstream_status", "latency_ms", "reason", "trust_score",
}

// silencedKeys sont les champs que `pretty` n'affiche jamais : redondants à
// l'écran (ip_hash double ip) ou trop verbeux pour une ligne de console. Ils
// restent présents en format json, qui est le format d'audit.
var silencedKeys = map[string]bool{
	"ip_hash":        true,
	"waf_latency_ms": true,
	"cf_ray":         true,
}

// prettyHandler rend un événement de sécurité sur une ligne lisible par un
// humain (FR-09, `logging.format: pretty`).
//
// Ce format est explicitement HORS du contrat d'audit : il promeut, omet et
// abrège des champs. Il existe pour le développement local, là où lire du JSON
// à l'œil coûte plus cher que la perte d'information.
type prettyHandler struct {
	out    io.Writer
	level  slog.Level
	colors bool

	// mu sérialise l'écriture : une ligne doit sortir d'un seul Write, sinon
	// deux requêtes concurrentes entrelacent leurs fragments à l'écran.
	mu    *sync.Mutex
	attrs []slog.Attr
}

func newPrettyHandler(out io.Writer, level slog.Level, colors bool) *prettyHandler {
	return &prettyHandler{out: out, level: level, colors: colors, mu: &sync.Mutex{}}
}

func (h *prettyHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *prettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	merged := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	merged = append(merged, h.attrs...)
	merged = append(merged, attrs...)
	return &prettyHandler{out: h.out, level: h.level, colors: h.colors, mu: h.mu, attrs: merged}
}

// WithGroup applique le nom de groupe en préfixe des clés suivantes. Le WAF
// n'émet pas de groupes (WriteSecurityEvent est plat) ; l'implémentation reste
// correcte pour ne pas perdre d'attributs si un appelant en introduit.
func (h *prettyHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &groupedHandler{parent: h, prefix: name + "."}
}

func (h *prettyHandler) Handle(_ context.Context, record slog.Record) error {
	fields := make(map[string]string, record.NumAttrs()+len(h.attrs))
	order := make([]string, 0, record.NumAttrs()+len(h.attrs))

	collect := func(attr slog.Attr) {
		key, value, ok := renderAttr(attr)
		if !ok || silencedKeys[key] {
			return
		}
		if _, seen := fields[key]; !seen {
			order = append(order, key)
		}
		fields[key] = value
	}
	for _, attr := range h.attrs {
		collect(attr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		collect(attr)
		return true
	})

	line := h.compose(record, fields, order)

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.out, line)
	return err
}

// compose assemble la ligne : horodatage, action colorisée, requête, puis les
// champs restants en clé=valeur.
func (h *prettyHandler) compose(record slog.Record, fields map[string]string, order []string) string {
	var b strings.Builder

	b.WriteString(h.paint(ansiDim, shortTime(fields["timestamp"], record.Time)))
	b.WriteByte(' ')
	action := fields["action"]
	if action == "" {
		action = strings.ToUpper(record.Level.String())
	}
	b.WriteString(h.paint(actionColor(action), fmt.Sprintf("%-13s", action)))

	if ip := fields["ip"]; ip != "" {
		b.WriteByte(' ')
		b.WriteString(ip)
	}
	if method := fields["method"]; method != "" {
		b.WriteByte(' ')
		b.WriteString(method)
	}
	if target := fields["domain"] + fields["path"]; target != "" {
		b.WriteByte(' ')
		b.WriteString(target)
	}
	if status := fields["upstream_status"]; status != "" {
		b.WriteByte(' ')
		b.WriteString(status)
	}
	if latency := fields["latency_ms"]; latency != "" {
		b.WriteByte(' ')
		b.WriteString(latency + "ms")
	}
	if reason := fields["reason"]; reason != "" {
		b.WriteByte(' ')
		b.WriteString(h.paint(ansiDim, "reason=") + reason)
	}
	if score, ok := fields["trust_score"]; ok {
		b.WriteByte(' ')
		b.WriteString(h.paint(ansiDim, "score=") + score)
	}

	// Le reste dans l'ordre d'émission : rien n'est perdu au-delà des champs
	// explicitement silencieux, seul l'ordre de lecture est retravaillé.
	for _, key := range order {
		if isPromoted(key) {
			continue
		}
		value := fields[key]
		if value == "" || value == "0" || value == "false" {
			continue // bruit de fond : un champ à sa valeur neutre n'apprend rien
		}
		b.WriteByte(' ')
		b.WriteString(h.paint(ansiDim, key+"=") + value)
	}
	b.WriteByte('\n')
	return b.String()
}

func (h *prettyHandler) paint(color string, text string) string {
	if !h.colors || color == "" {
		return text
	}
	return color + text + ansiReset
}

// groupedHandler préfixe les clés d'un groupe slog. Il délègue tout le rendu au
// prettyHandler : un seul chemin de formatage, une seule sérialisation.
type groupedHandler struct {
	parent *prettyHandler
	prefix string
}

func (h *groupedHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.parent.Enabled(ctx, level)
}

func (h *groupedHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	prefixed := make([]slog.Attr, 0, len(attrs))
	for _, attr := range attrs {
		prefixed = append(prefixed, slog.Attr{Key: h.prefix + attr.Key, Value: attr.Value})
	}
	next, _ := h.parent.WithAttrs(prefixed).(*prettyHandler)
	return &groupedHandler{parent: next, prefix: h.prefix}
}

func (h *groupedHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &groupedHandler{parent: h.parent, prefix: h.prefix + name + "."}
}

func (h *groupedHandler) Handle(ctx context.Context, record slog.Record) error {
	prefixed := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)
	record.Attrs(func(attr slog.Attr) bool {
		prefixed.AddAttrs(slog.Attr{Key: h.prefix + attr.Key, Value: attr.Value})
		return true
	})
	return h.parent.Handle(ctx, prefixed)
}

// renderAttr formate un attribut. Le second retour est false pour un attribut
// à ignorer : les clés intégrées de slog (déjà retirées côté json par
// dropBuiltinKeys) et les valeurs nulles produites par nullableInt/nullableString.
func renderAttr(attr slog.Attr) (string, string, bool) {
	switch attr.Key {
	case slog.TimeKey, slog.LevelKey, slog.MessageKey:
		return "", "", false
	}
	value := attr.Value.Resolve()
	switch value.Kind() {
	case slog.KindAny:
		if value.Any() == nil {
			return "", "", false
		}
		return attr.Key, fmt.Sprint(value.Any()), true
	case slog.KindFloat64:
		// Arrondi au centième : une latence de 3528.8813999999998 ms est du bruit
		// à l'écran. Le format json, lui, garde la valeur exacte.
		rounded := math.Round(value.Float64()*100) / 100
		return attr.Key, strconv.FormatFloat(rounded, 'f', -1, 64), true
	default:
		return attr.Key, value.String(), true
	}
}

func isPromoted(key string) bool {
	for _, promoted := range promotedKeys {
		if key == promoted {
			return true
		}
	}
	return false
}

// shortTime réduit l'horodatage à l'heure du jour : sur une console, la date
// est constante et l'année n'apprend rien. Le format json garde l'horodatage
// complet (RFC3339Nano).
func shortTime(timestamp string, fallback time.Time) string {
	if parsed, err := time.Parse(time.RFC3339Nano, timestamp); err == nil {
		return parsed.Local().Format("15:04:05.000")
	}
	if !fallback.IsZero() {
		return fallback.Local().Format("15:04:05.000")
	}
	return "--:--:--.---"
}

func actionColor(action string) string {
	switch action {
	case ActionBlock:
		return ansiRed
	case ActionCircuitBreak:
		return ansiBrightRed
	case ActionRateLimit:
		return ansiMagenta
	case ActionChallenge:
		return ansiYellow
	case ActionHoneypot:
		return ansiCyan
	case ActionPass:
		return ansiGreen
	default:
		return ""
	}
}

// colorsEnabled décide de la colorisation : jamais hors terminal (un fichier de
// log truffé de séquences ANSI est illisible et casse les greps), et jamais
// quand NO_COLOR est défini — la convention respectée par les outils CLI.
func colorsEnabled(format string, output *os.File) bool {
	if format != formatPretty {
		return false
	}
	if _, noColor := os.LookupEnv("NO_COLOR"); noColor {
		return false
	}
	return isTerminal(output)
}

func isTerminal(file *os.File) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
