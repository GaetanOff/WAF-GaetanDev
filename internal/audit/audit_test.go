package audit

import "testing"

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
	for i := 0; i < 5; i++ {
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
