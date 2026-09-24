package cluster

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/storage"
)

type eventSchema struct {
	Required   []string `json:"required"`
	Properties map[string]struct {
		Enum    []string `json:"enum"`
		Pattern string   `json:"pattern"`
	} `json:"properties"`
}

// Conformance : chaque événement publié respecte
// specs/schemas/cluster-event.schema.json (clés, champs requis par type,
// motifs).
func TestPublishedEventsMatchClusterEventSchema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "specs", "schemas", "cluster-event.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema eventSchema
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	bus := &capturingBus{}
	syncer := NewSyncer(bus, nil, nil)
	until := time.Now().Add(time.Minute)
	for _, event := range []Event{
		{Type: EventBlacklistAdd, Value: "5.5.5.5"},
		{Type: EventCircuitOpen, IPHash: "0123456789abcdef", Until: &until},
		{Type: EventScoreCritical, IPHash: "0123456789abcdef", Domain: "example.test", Score: 3},
	} {
		syncer.Publish(t.Context(), event)
	}
	syncer.PublishScoreCritical(storage.VisitorState{IPHash: "0123456789abcdef", Score: 0})
	syncer.Publish(t.Context(), <-syncer.outbox)

	requiredByType := map[string]string{EventBlacklistAdd: "value", EventScoreCritical: "ip_hash", EventCircuitOpen: "ip_hash"}
	for _, payload := range bus.payloads {
		var document map[string]any
		if err := json.Unmarshal(payload, &document); err != nil {
			t.Fatalf("decode event: %v", err)
		}
		for _, name := range schema.Required {
			if _, ok := document[name]; !ok {
				t.Fatalf("event %s missing required %q", payload, name)
			}
		}
		for name, value := range document {
			property, ok := schema.Properties[name]
			if !ok {
				t.Fatalf("event %s has property %q absent from the schema", payload, name)
			}
			text, isText := value.(string)
			if len(property.Enum) > 0 && !slices.Contains(property.Enum, text) {
				t.Fatalf("event %s: %q = %v not in %v", payload, name, value, property.Enum)
			}
			if property.Pattern != "" && isText && !regexp.MustCompile(property.Pattern).MatchString(text) {
				t.Fatalf("event %s: %q = %q does not match %s", payload, name, text, property.Pattern)
			}
		}
		if field := requiredByType[document["type"].(string)]; field != "" {
			if _, ok := document[field]; !ok {
				t.Fatalf("event %s missing %q required for its type", payload, field)
			}
		}
	}
}

type capturingBus struct{ payloads [][]byte }

func (b *capturingBus) Publish(_ context.Context, event Event) error {
	payload, err := encode(event)
	b.payloads = append(b.payloads, payload)
	return err
}

func (b *capturingBus) Subscribe(context.Context, func(Event)) error { return nil }
func (b *capturingBus) Close() error                                 { return nil }
