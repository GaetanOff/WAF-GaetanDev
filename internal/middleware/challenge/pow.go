package challenge

import (
	"crypto/sha256"
	"strconv"
)

func ValidatePow(token string, nonce string, difficultyBits int) bool {
	if difficultyBits < 0 || difficultyBits > 256 {
		return false
	}
	if _, err := strconv.ParseUint(nonce, 10, 64); err != nil {
		return false
	}

	sum := sha256.Sum256([]byte(token + nonce))
	return hasLeadingZeroBits(sum[:], difficultyBits)
}

func hasLeadingZeroBits(hash []byte, difficultyBits int) bool {
	fullBytes := difficultyBits / 8
	remainingBits := difficultyBits % 8

	for i := 0; i < fullBytes; i++ {
		if hash[i] != 0 {
			return false
		}
	}
	if remainingBits == 0 {
		return true
	}

	mask := byte(0xFF << (8 - remainingBits))
	return hash[fullBytes]&mask == 0
}
