package challenge

import (
	"crypto/sha256"
	"encoding/hex"
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

// runPowBlock exécute driver après le bloc Proof-of-Work de la page, sous Node.
func runPowBlock(t *testing.T, driver string) string {
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
	output, err := exec.Command(node, "-e", content[start:end]+driver).Output()
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
	bitsCases := []int{0, 1, 5, 10, 13} // non multiples de 4
	// Token réaliste (> 64 octets) : le midstate du préfixe est exercé.
	tokenFor := func(bits int) string {
		return strings.Repeat("eyJpcF9oYXNoIjoi", 6) + "." + strconv.Itoa(bits)
	}
	driver := "(async function () { var out = [];"
	for _, bits := range bitsCases {
		driver += "out.push((await solvePow(" + strconv.Quote(tokenFor(bits)) + ", " + strconv.Itoa(bits) + ")).nonce);"
	}
	driver += "process.stdout.write(out.join(' ')); })();"
	nonces := strings.Fields(runPowBlock(t, driver))
	if len(nonces) != len(bitsCases) {
		t.Fatalf("page solver returned %d nonces, want %d", len(nonces), len(bitsCases))
	}
	for i, bits := range bitsCases {
		token, got := tokenFor(bits), nonces[i]
		if !ValidatePow(token, got, bits) {
			t.Fatalf("bits=%d: page nonce %q rejected by the server", bits, got)
		}
		if want := firstValidNonce(t, token, bits); got != want {
			t.Fatalf("bits=%d: page nonce = %s, want %s (the client demands more work than the server)", bits, got, want)
		}
	}
}

// Le hash synchrone de la page (midstate du préfixe + suffixe) doit égaler
// SHA-256 pour toute longueur de préfixe : blocs complets compressés une seule
// fois, et frontières de padding (56 octets) franchies par le nonce.
func TestPageHasherMatchesSHA256(t *testing.T) {
	suffixes := []string{"0", "7", "12345", "9999999999"}
	output := runPowBlock(t, `
var lines = [];
for (var length = 0; length <= 200; length++) {
  var hash = prefixHasher("x".repeat(length));
  ["0", "7", "12345", "9999999999"].forEach(function (suffix) {
    lines.push(Array.from(hash(suffix), function (b) { return b.toString(16).padStart(2, "0"); }).join(""));
  });
}
process.stdout.write(lines.join(" "));
`)
	lines := strings.Fields(output)
	index := 0
	for length := 0; length <= 200; length++ {
		for _, suffix := range suffixes {
			sum := sha256.Sum256([]byte(strings.Repeat("x", length) + suffix))
			if want := hex.EncodeToString(sum[:]); index >= len(lines) || lines[index] != want {
				t.Fatalf("prefix length %d, suffix %q: page hash differs from SHA-256", length, suffix)
			}
			index++
		}
	}
}
