package signing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

func Sign(key []byte, payload string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func Verify(key []byte, payload string, sig string) bool {
	expected, err := base64.RawURLEncoding.DecodeString(Sign(key, payload))
	if err != nil {
		return false
	}
	actual, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	return hmac.Equal(actual, expected)
}

// Derive dérive du secret une clé propre à un usage (HMAC-SHA256(secret,
// purpose)). Deux objets signés avec des clés dérivées d'usages distincts ne
// sont jamais interchangeables, même s'ils partagent le même format : le token
// de challenge, remis à tout visiteur, était accepté comme cookie de clearance.
func Derive(secret []byte, purpose string) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(purpose))
	return mac.Sum(nil)
}
