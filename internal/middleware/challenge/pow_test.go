package challenge

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
)

func TestValidatePowKnownVector(t *testing.T) {
	token := "known-token"
	nonce, hashHex := solvePowForTest(t, token, 16)

	if !ValidatePow(token, nonce, 16) {
		t.Fatalf("ValidatePow() false for nonce=%s hash=%s", nonce, hashHex)
	}
}

func TestValidatePowRejectsInvalidNonce(t *testing.T) {
	if ValidatePow("token", "not-a-number", 16) {
		t.Fatal("expected invalid nonce to be rejected")
	}
}

func TestValidatePowRejectsInsufficientDifficulty(t *testing.T) {
	token := "known-token"
	nonce, _ := solvePowForTest(t, token, 8)

	if ValidatePow(token, nonce, 24) {
		t.Fatal("expected nonce for lower difficulty to fail higher difficulty")
	}
}

func TestHasLeadingZeroBitsSupportsPartialBytes(t *testing.T) {
	hash := []byte{0x07}
	if !hasLeadingZeroBits(hash, 5) {
		t.Fatal("expected 0x07 to satisfy 5 leading zero bits")
	}
	if hasLeadingZeroBits(hash, 6) {
		t.Fatal("expected 0x07 to fail 6 leading zero bits")
	}
}

func solvePowForTest(t *testing.T, token string, difficultyBits int) (string, string) {
	t.Helper()

	for nonce := uint64(0); nonce < 10_000_000; nonce++ {
		nonceText := strconv.FormatUint(nonce, 10)
		hash := sha256.Sum256([]byte(token + nonceText))
		if hasLeadingZeroBits(hash[:], difficultyBits) {
			return nonceText, hex.EncodeToString(hash[:])
		}
	}

	t.Fatalf("could not solve test PoW")
	return "", ""
}
