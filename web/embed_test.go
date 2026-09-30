package web

import (
	"html/template"
	"regexp"
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

// FR-06 : sous la CSP à nonce, un <script> ou un <style> sans le nonce ne
// s'exécute pas, et un gestionnaire d'événement inline (onclick=…) non plus.
func TestChallengePageInlineCodeCarriesTheNonce(t *testing.T) {
	tags := regexp.MustCompile(`(?i)<(script|style)\b[^>]*>`).FindAllString(ChallengePage, -1)
	if len(tags) == 0 {
		t.Fatal("no inline <script> or <style> found in the challenge page")
	}
	for _, tag := range tags {
		if !strings.Contains(tag, `nonce="{{.Nonce}}"`) {
			t.Errorf("%s lacks nonce=\"{{.Nonce}}\"", tag)
		}
	}
	if handler := regexp.MustCompile(`(?i)<[^>]+\son[a-z]+\s*=`).FindString(ChallengePage); handler != "" {
		t.Errorf("inline event handler %q is blocked by the CSP", handler)
	}
	if style := regexp.MustCompile(`(?i)<[^>]+\sstyle\s*=`).FindString(ChallengePage); style != "" {
		t.Errorf("inline style attribute %q is blocked by the CSP", style)
	}
}
