package web

import (
	"html/template"
	"strings"
	"testing"
)

func TestChallengePageIsEmbeddedAndParses(t *testing.T) {
	if !strings.Contains(ChallengePage, "{{.Token}}") {
		t.Fatal("embedded challenge page is missing the token placeholder")
	}
	if _, err := template.New("challenge").Parse(ChallengePage); err != nil {
		t.Fatalf("embedded challenge page does not parse: %v", err)
	}
}
