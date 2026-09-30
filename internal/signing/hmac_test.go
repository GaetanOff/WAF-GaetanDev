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

func TestDeriveSeparatesPurposes(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	token := Derive(secret, "token")
	cookie := Derive(secret, "cookie")

	sig := Sign(token, "payload")
	if Verify(cookie, "payload", sig) {
		t.Fatal("a signature made for one purpose must not verify for another")
	}
	if !Verify(Derive(secret, "token"), "payload", sig) {
		t.Fatal("derivation must be deterministic")
	}
}
