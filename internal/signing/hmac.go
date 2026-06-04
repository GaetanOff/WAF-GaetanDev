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
