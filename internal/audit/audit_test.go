package audit

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordAndList(t *testing.T) {
	trail, err := NewTrail(10, "")
	if err != nil {
		t.Fatalf("NewTrail() error = %v", err)
	}
	trail.Record("add_blacklist", "1.2.3.4", "created")
	trail.Record("remove_whitelist", "5.6.7.8", "removed")

	entries := trail.List()
	if len(entries) != 2 {
		t.Fatalf("len = %d, want 2", len(entries))
	}
	if entries[0].Action != "add_blacklist" || entries[0].Target != "1.2.3.4" {
		t.Fatalf("entry[0] = %+v", entries[0])
	}
	if entries[0].Timestamp == "" {
		t.Fatal("timestamp not set")
	}
}

func TestFIFORotation(t *testing.T) {
	trail, _ := NewTrail(3, "")
	for range 5 {
		trail.Record("action", "target", "ok")
	}
	if got := len(trail.List()); got != 3 {
		t.Fatalf("len = %d, want 3 (FIFO cap)", got)
	}
}

func TestSecretsMasked(t *testing.T) {
	trail, _ := NewTrail(10, "")
	trail.Record("config_patch", "admin_token=supersecretvalue", "applied")
	trail.Record("add_blacklist", "1.2.3.4", "created")

	entries := trail.List()
	if entries[0].Target != "***" {
		t.Fatalf("secret target = %q, want ***", entries[0].Target)
	}
	if entries[1].Target != "1.2.3.4" {
		t.Fatalf("non-secret target masked: %q", entries[1].Target)
	}
}

// Un échec d'écriture du fichier d'audit est journalisé, et l'entrée reste
// consultable en mémoire. Il était ignoré : la piste d'audit se perdait en
// silence (disque plein, fichier révoqué).
func TestFileExportFailureIsLogged(t *testing.T) {
	trail, err := NewTrail(10, filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("NewTrail() error = %v", err)
	}
	_ = trail.file.Close() // toute écriture suivante échoue
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	trail.Record("add_blacklist", "1.2.3.4", "created")

	if !strings.Contains(logs.String(), "audit file export failed") {
		t.Fatalf("logs = %q, want the export failure reported", logs.String())
	}
	if entries := trail.List(); len(entries) != 1 {
		t.Fatalf("entries = %v, want the entry kept in memory", entries)
	}
}
