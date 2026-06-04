package signing

import "testing"

func TestSignVerify(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	payload := "payload"

	sig := Sign(key, payload)
	if sig == "" {
		t.Fatal("signature is empty")
	}
	if !Verify(key, payload, sig) {
		t.Fatal("expected signature to verify")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	sig := Sign(key, "payload")

	if Verify(key, "tampered", sig) {
		t.Fatal("expected tampered payload to be rejected")
	}
}

func TestVerifyRejectsInvalidSignatureEncoding(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	if Verify(key, "payload", "not base64!") {
		t.Fatal("expected invalid signature encoding to be rejected")
	}
}
