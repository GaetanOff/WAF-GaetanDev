package challenge

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/trust"
)

func TestTokenGenerateValidate(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	issuer := NewTokenIssuer(testKey, 30*time.Second)
	issuer.Now = func() time.Time { return now }

	token, err := issuer.Generate("1.2.3.4", "example.com")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	payload, err := issuer.Validate(token, "1.2.3.4", "example.com")
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if payload.IPHash != trust.HashIP("1.2.3.4") {
		t.Fatalf("IPHash = %q, want hash", payload.IPHash)
	}
}

func TestTokenFacadeGenerateValidate(t *testing.T) {
	token, err := GenerateToken("1.2.3.4", "example.com", testKey, 30*time.Second)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	if _, err := ValidateToken(token, "1.2.3.4", "example.com", testKey); err != nil {
		t.Fatalf("ValidateToken() error = %v", err)
	}
}

func TestTokenRejectsExpired(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	issuer := NewTokenIssuer(testKey, 30*time.Second)
	issuer.Now = func() time.Time { return now }

	token, err := issuer.Generate("1.2.3.4", "example.com")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	issuer.Now = func() time.Time { return now.Add(31 * time.Second) }

	_, err = issuer.Validate(token, "1.2.3.4", "example.com")
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("Validate() error = %v, want ErrTokenExpired", err)
	}
}

func TestTokenRejectsForgedSignature(t *testing.T) {
	issuer := NewTokenIssuer(testKey, 30*time.Second)
	token, err := issuer.Generate("1.2.3.4", "example.com")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	parts := strings.Split(token, ".")
	forged := parts[0] + "." + strings.Repeat("A", len(parts[1]))
	_, err = issuer.Validate(forged, "1.2.3.4", "example.com")
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("Validate() error = %v, want ErrTokenInvalid", err)
	}
}

func TestTokenRejectsIPMismatch(t *testing.T) {
	issuer := NewTokenIssuer(testKey, 30*time.Second)
	token, err := issuer.Generate("1.2.3.4", "example.com")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	_, err = issuer.Validate(token, "5.6.7.8", "example.com")
	if !errors.Is(err, ErrTokenIPMismatch) {
		t.Fatalf("Validate() error = %v, want ErrTokenIPMismatch", err)
	}
}

func TestTokenRejectsDomainMismatch(t *testing.T) {
	issuer := NewTokenIssuer(testKey, 30*time.Second)
	token, err := issuer.Generate("1.2.3.4", "example.com")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	_, err = issuer.Validate(token, "1.2.3.4", "other.example.com")
	if !errors.Is(err, ErrTokenDomainMismatch) {
		t.Fatalf("Validate() error = %v, want ErrTokenDomainMismatch", err)
	}
}
