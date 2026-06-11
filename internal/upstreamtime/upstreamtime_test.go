package upstreamtime

import (
	"context"
	"testing"
	"time"
)

func TestRecorderNilIsSafe(t *testing.T) {
	var r *Recorder
	r.Add(time.Second) // ne doit pas paniquer
	if r.Total() != 0 {
		t.Fatalf("nil Recorder Total = %v, want 0", r.Total())
	}
	if FromContext(context.Background()) != nil {
		t.Fatal("FromContext sans recorder doit être nil")
	}
}

func TestRecorderAccumulates(t *testing.T) {
	ctx, rec := WithRecorder(context.Background())
	if FromContext(ctx) != rec {
		t.Fatal("FromContext ne retrouve pas le recorder")
	}
	rec.Add(30 * time.Millisecond)
	rec.Add(20 * time.Millisecond)
	rec.Add(-5 * time.Millisecond) // négatif ignoré
	if got := rec.Total(); got != 50*time.Millisecond {
		t.Fatalf("Total = %v, want 50ms", got)
	}
}
