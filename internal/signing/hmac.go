package signing

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

func Sign(key []byte, payload string) string {
	return base64.RawURLEncoding.EncodeToString(sum(key, payload))
}

func sum(key []byte, payload string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(payload))
	return mac.Sum(nil)
}

// Verify compare la signature décodée au HMAC brut : Sign encodait le HMAC
// attendu en Base64 pour aussitôt le redécoder, à chaque cookie de clearance.
func Verify(key []byte, payload string, sig string) bool {
	actual, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	return hmac.Equal(actual, sum(key, payload))
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

// EqualSecret compare en temps constant une valeur reçue (token Bearer…) au
// secret attendu. subtle.ConstantTimeCompare rend la main dès que les
// longueurs diffèrent : comparer les chaînes brutes révélait la longueur du
// secret par le temps de réponse. Les empreintes SHA-256, de longueur fixe, ne
// révèlent rien.
func EqualSecret(got string, want string) bool {
	gotDigest := sha256.Sum256([]byte(got))
	wantDigest := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gotDigest[:], wantDigest[:]) == 1
}
