package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
)

func prettyConfig() config.Logging {
	cfg := config.Default().Logging
	cfg.Format = formatPretty
	return cfg
}

func blockEvent() SecurityEvent {
	status := 403
	return SecurityEvent{
		Timestamp:      time.Date(2026, 9, 2, 14, 5, 6, 700000000, time.UTC).Format(time.RFC3339Nano),
		RequestID:      "req-1234",
		IP:             "203.0.113.20",
		IPHash:         "d0d0cafe",
		Domain:         "example.test",
		Method:         "GET",
		Path:           "/login",
		UserAgent:      "curl/8.6.0",
		Action:         ActionBlock,
		Reason:         "score_below_block_threshold",
		TrustScore:     12,
		ScoreDelta:     -10,
		RiskScore:      87,
		RiskDecision:   "BLOCK",
		LatencyMS:      1.5,
		UpstreamStatus: &status,
	}
}

func TestPrettyFormatRendersOneHumanReadableLine(t *testing.T) {
	var output bytes.Buffer
	log := NewWithWriter(prettyConfig(), &output)

	log.WriteSecurityEvent(blockEvent())

	line := output.String()
	t.Logf("pretty line: %s", strings.TrimRight(line, "\n"))
	if strings.Count(line, "\n") != 1 {
		t.Fatalf("output = %q, want exactly one line", line)
	}
	for _, want := range []string{"BLOCK", "203.0.113.20", "GET", "example.test/login", "403", "1.5ms", "reason=score_below_block_threshold", "score=12"} {
		if !strings.Contains(line, want) {
			t.Fatalf("line = %q, want it to contain %q", line, want)
		}
	}
	// Une ligne pretty n'est pas du JSON : c'est justement le point du format.
	if strings.HasPrefix(strings.TrimSpace(line), "{") {
		t.Fatalf("line = %q, want a console rendering, not JSON", line)
	}
}

// La colorisation n'est jamais posée sur un writer quelconque : NewWithWriter
// est le chemin des tests et des sorties redirigées.
func TestPrettyFormatDoesNotColorizeANonTerminalWriter(t *testing.T) {
	var output bytes.Buffer
	log := NewWithWriter(prettyConfig(), &output)

	log.WriteSecurityEvent(blockEvent())

	if strings.Contains(output.String(), "\x1b[") {
		t.Fatalf("line = %q, want no ANSI escape when the destination is not a terminal", output.String())
	}
}

func TestPrettyFormatColorizesActionWhenColorsAreEnabled(t *testing.T) {
	cases := []struct {
		action string
		color  string
	}{
		{action: ActionBlock, color: ansiRed},
		{action: ActionChallenge, color: ansiYellow},
		{action: ActionRateLimit, color: ansiMagenta},
		{action: ActionPass, color: ansiGreen},
		{action: ActionCircuitBreak, color: ansiBrightRed},
		{action: ActionHoneypot, color: ansiCyan},
	}

	for _, testCase := range cases {
		t.Run(testCase.action, func(t *testing.T) {
			var output bytes.Buffer
			log := newLogger(prettyConfig(), &output, true)
			event := blockEvent()
			event.Action = testCase.action

			log.WriteSecurityEvent(event)

			if !strings.Contains(output.String(), testCase.color+testCase.action) {
				t.Fatalf("line = %q, want action %s painted with %q", output.String(), testCase.action, testCase.color)
			}
			if !strings.Contains(output.String(), ansiReset) {
				t.Fatalf("line = %q, want the color to be reset", output.String())
			}
		})
	}
}

// Les champs absents (nullableInt / nullableString) ne doivent pas produire de
// « <nil> » à l'écran, et les champs silencieux restent hors du rendu console.
func TestPrettyFormatOmitsNullAndSilencedFields(t *testing.T) {
	var output bytes.Buffer
	log := NewWithWriter(prettyConfig(), &output)
	event := blockEvent()
	event.UpstreamStatus = nil

	log.WriteSecurityEvent(event)

	line := output.String()
	for _, unwanted := range []string{"<nil>", "null", "cf_ray", "d0d0cafe", "waf_latency_ms"} {
		if strings.Contains(line, unwanted) {
			t.Fatalf("line = %q, want it to omit %q", line, unwanted)
		}
	}
	// Les champs présents mais non promus restent lisibles en clé=valeur.
	for _, want := range []string{"request_id=req-1234", "risk_score=87", "risk_decision=BLOCK", "score_delta=-10"} {
		if !strings.Contains(line, want) {
			t.Fatalf("line = %q, want it to contain %q", line, want)
		}
	}
}

// FR-09 : le format json reste le défaut et le contrat d'audit — il n'est pas
// touché par l'ajout du rendu console.
func TestJSONFormatRemainsTheAuditContract(t *testing.T) {
	var output bytes.Buffer
	log := NewWithWriter(config.Default().Logging, &output)

	log.WriteSecurityEvent(blockEvent())

	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v (output = %q)", err, output.String())
	}
	for _, key := range []string{"timestamp", "request_id", "ip", "ip_hash", "domain", "method", "path", "action", "reason", "trust_score", "waf_latency_ms"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("json log is missing %q — the audit contract must stay complete", key)
		}
	}
	if strings.Contains(output.String(), "\x1b[") {
		t.Fatalf("json output = %q, want no ANSI escape", output.String())
	}
}

// Le format ne change pas le filtrage par niveau.
func TestPrettyHandlerHonorsLevel(t *testing.T) {
	var output bytes.Buffer
	handler := newPrettyHandler(&output, slog.LevelWarn, false)

	if handler.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("info must be filtered out by a warn-level handler")
	}
	if !handler.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("error must pass a warn-level handler")
	}
}

// Deux requêtes concurrentes ne doivent pas entrelacer leurs fragments : une
// ligne sort d'un seul Write.
func TestPrettyHandlerWritesWholeLinesUnderConcurrency(t *testing.T) {
	var output bytes.Buffer
	log := NewWithWriter(prettyConfig(), &output)

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.WriteSecurityEvent(blockEvent())
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimRight(output.String(), "\n"), "\n")
	if len(lines) != 50 {
		t.Fatalf("lines = %d, want 50", len(lines))
	}
	for i, line := range lines {
		if !strings.Contains(line, "reason=score_below_block_threshold") {
			t.Fatalf("line %d is truncated or interleaved: %q", i, line)
		}
	}
}

// Un attribut inconnu du contrat (ajouté par un appelant, ou par un groupe
// slog) reste visible : le rendu console n'est pas une liste blanche figée.
func TestPrettyHandlerKeepsUnknownAndGroupedAttributes(t *testing.T) {
	var output bytes.Buffer
	handler := newPrettyHandler(&output, slog.LevelInfo, false)
	logger := slog.New(handler).With(slog.String("component", "tarpit")).WithGroup("upstream")

	logger.Info("", slog.String("pool", "backup"))

	line := output.String()
	if !strings.Contains(line, "component=tarpit") {
		t.Fatalf("line = %q, want it to keep the With() attribute", line)
	}
	if !strings.Contains(line, "upstream.pool=backup") {
		t.Fatalf("line = %q, want it to keep the grouped attribute", line)
	}
}

func TestColorsEnabled(t *testing.T) {
	regularFile, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = regularFile.Close() })

	// os.DevNull est un périphérique caractère sur Windows comme sur Unix : il
	// tient le rôle du terminal pour ce test, sans dépendre d'un vrai TTY.
	charDevice, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile(%s) error = %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = charDevice.Close() })
	if !isTerminal(charDevice) {
		t.Skipf("%s is not reported as a character device on this platform", os.DevNull)
	}

	if colorsEnabled("json", charDevice) {
		t.Fatal("json must never be colorized")
	}
	if colorsEnabled(formatPretty, regularFile) {
		t.Fatal("pretty must not be colorized when the destination is a regular file")
	}
	if !colorsEnabled(formatPretty, charDevice) {
		t.Fatal("pretty must be colorized on a terminal")
	}

	t.Setenv("NO_COLOR", "1")
	if colorsEnabled(formatPretty, charDevice) {
		t.Fatal("NO_COLOR must disable colorization")
	}
}

func TestIsTerminalRejectsRegularFilesAndNil(t *testing.T) {
	regularFile, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = regularFile.Close() })

	if isTerminal(regularFile) {
		t.Fatal("a regular file is not a terminal")
	}
	if isTerminal(nil) {
		t.Fatal("nil is not a terminal")
	}
}
