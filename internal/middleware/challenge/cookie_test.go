package challenge

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/trust"
)

const testKey = "0123456789abcdef0123456789abcdef"

func TestCookieIssueValidate(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	issuer := NewCookieIssuer("waf_session", testKey)
	issuer.Now = func() time.Time { return now }

	cookie, err := issuer.Issue("1.2.3.4", "example.com", "fingerprint", 75, time.Hour)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	payload, err := issuer.Validate(cookie.Value, "1.2.3.4", "example.com")
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if payload.IPHash != trust.HashIP("1.2.3.4") {
		t.Fatalf("IPHash = %q, want hash", payload.IPHash)
	}
	if payload.Score != 75 {
		t.Fatalf("Score = %d, want 75", payload.Score)
	}
	if cookie.HttpOnly != true || cookie.Secure != true {
		t.Fatalf("expected secure httponly cookie")
	}
}

func TestCookieFacadeIssueValidate(t *testing.T) {
	cookie, err := Issue("waf_session", testKey, "1.2.3.4", "example.com", "fingerprint", 75, time.Hour)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	payload, err := Validate(cookie.Value, "1.2.3.4", "example.com", testKey)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if payload.Score != 75 {
		t.Fatalf("Score = %d, want 75", payload.Score)
	}
}

func TestCookieValidateRejectsExpired(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	issuer := NewCookieIssuer("waf_session", testKey)
	issuer.Now = func() time.Time { return now }

	cookie, err := issuer.Issue("1.2.3.4", "example.com", "fingerprint", 75, time.Second)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	issuer.Now = func() time.Time { return now.Add(2 * time.Second) }
	_, err = issuer.Validate(cookie.Value, "1.2.3.4", "example.com")
	if !errors.Is(err, ErrCookieExpired) {
		t.Fatalf("Validate() error = %v, want ErrCookieExpired", err)
	}
}

func TestCookieValidateRejectsForgedHMAC(t *testing.T) {
	issuer := NewCookieIssuer("waf_session", testKey)
	cookie, err := issuer.Issue("1.2.3.4", "example.com", "fingerprint", 75, time.Hour)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	parts := strings.Split(cookie.Value, ".")
	forged := parts[0] + "." + strings.Repeat("A", len(parts[1]))
	_, err = issuer.Validate(forged, "1.2.3.4", "example.com")
	if !errors.Is(err, ErrCookieInvalid) {
		t.Fatalf("Validate() error = %v, want ErrCookieInvalid", err)
	}
}

func TestCookieValidateRejectsIPMismatch(t *testing.T) {
	issuer := NewCookieIssuer("waf_session", testKey)
	cookie, err := issuer.Issue("1.2.3.4", "example.com", "fingerprint", 75, time.Hour)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	_, err = issuer.Validate(cookie.Value, "5.6.7.8", "example.com")
	if !errors.Is(err, ErrCookieIPMismatch) {
		t.Fatalf("Validate() error = %v, want ErrCookieIPMismatch", err)
	}
}

func TestCookieValidateRejectsDomainMismatch(t *testing.T) {
	issuer := NewCookieIssuer("waf_session", testKey)
	cookie, err := issuer.Issue("1.2.3.4", "example.com", "fingerprint", 75, time.Hour)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	_, err = issuer.Validate(cookie.Value, "1.2.3.4", "other.example.com")
	if !errors.Is(err, ErrCookieDomainMismatch) {
		t.Fatalf("Validate() error = %v, want ErrCookieDomainMismatch", err)
	}
}
