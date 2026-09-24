package challenge

import (
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	powBlockStart = "// ── Proof-of-Work"
	powBlockEnd   = "// ── Main challenge flow"
)

// runPageSolver exécute sous Node le bloc Proof-of-Work de web/challenge.html
// (le code réellement servi) et retourne le nonce trouvé. Skip si Node absent.
func runPageSolver(t *testing.T, token string, difficultyBits int) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed: the client-side solver cannot be exercised")
	}
	page, err := os.ReadFile(filepath.Join("..", "..", "..", "web", "challenge.html"))
	if err != nil {
		t.Fatalf("read challenge page: %v", err)
	}
	content := string(page)
	start := strings.Index(content, powBlockStart)
	end := strings.Index(content, powBlockEnd)
	if start < 0 || end < start {
		t.Fatalf("proof-of-work block not found between %q and %q", powBlockStart, powBlockEnd)
	}
	script := content[start:end] + `
Promise.resolve(solvePow(` + strconv.Quote(token) + `, ` + strconv.Itoa(difficultyBits) + `))
  .then(function (r) { process.stdout.write(r.nonce); });
`
	output, err := exec.Command(node, "-e", script).Output()
	if err != nil {
		t.Fatalf("run page solver: %v", err)
	}
	return string(output)
}

// firstValidNonce est la référence serveur : le plus petit nonce accepté par
// ValidatePow à cette difficulté.
func firstValidNonce(t *testing.T, token string, difficultyBits int) string {
	t.Helper()
	for nonce := range uint64(10_000_000) {
		text := strconv.FormatUint(nonce, 10)
		sum := sha256.Sum256([]byte(token + text))
		if hasLeadingZeroBits(sum[:], difficultyBits) {
			return text
		}
	}
	t.Fatal("no valid nonce found")
	return ""
}

// Régression : le client arrondissait la difficulté au chiffre hexadécimal
// supérieur (22 bits → 24) et résolvait jusqu'à 8× plus de hashes que demandé.
// Il doit trouver exactement le premier nonce que le serveur accepte.
func TestPageSolverMatchesServerBitRule(t *testing.T) {
	for _, bits := range []int{0, 1, 5, 10, 13} { // non multiples de 4
		token := "token-for-" + strconv.Itoa(bits)
		got := runPageSolver(t, token, bits)
		if !ValidatePow(token, got, bits) {
			t.Fatalf("bits=%d: page nonce %q rejected by the server", bits, got)
		}
		if want := firstValidNonce(t, token, bits); got != want {
			t.Fatalf("bits=%d: page nonce = %s, want %s (the client demands more work than the server)", bits, got, want)
		}
	}
}
