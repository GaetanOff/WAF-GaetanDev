package challenge

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gaetandev/waf/internal/signing"
	"github.com/gaetandev/waf/internal/trust"
)

const defaultCookiePath = "/"

var (
	ErrCookieMalformed      = errors.New("cookie malformed")
	ErrCookieInvalid        = errors.New("cookie invalid")
	ErrCookieExpired        = errors.New("cookie expired")
	ErrCookieIPMismatch     = errors.New("cookie ip mismatch")
	ErrCookieDomainMismatch = errors.New("cookie domain mismatch")
)

type CookieIssuer struct {
	Name string
	Key  []byte
	Now  func() time.Time
}

type Payload struct {
	IPHash    string `json:"ip_hash"`
	FPHash    string `json:"fp_hash"`
	Domain    string `json:"domain"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
	Score     int    `json:"score"`
}

func NewCookieIssuer(name string, key string) CookieIssuer {
	return CookieIssuer{
		Name: name,
		Key:  []byte(key),
		Now:  time.Now,
	}
}

func Issue(name string, key string, ip string, domain string, fpHash string, score int, ttl time.Duration) (http.Cookie, error) {
	return NewCookieIssuer(name, key).Issue(ip, domain, fpHash, score, ttl)
}

func Validate(cookieValue string, ip string, domain string, key string) (*Payload, error) {
	return NewCookieIssuer("", key).Validate(cookieValue, ip, domain)
}

func (i CookieIssuer) Issue(ip string, domain string, fpHash string, score int, ttl time.Duration) (http.Cookie, error) {
	now := i.now()
	payload := Payload{
		IPHash:    trust.HashIP(ip),
		FPHash:    fingerprintHash(fpHash),
		Domain:    domain,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
		Score:     clamp(score, 0, 100),
	}

	value, err := i.signPayload(payload)
	if err != nil {
		return http.Cookie{}, err
	}

	return http.Cookie{
		Name:     i.Name,
		Value:    value,
		Path:     defaultCookiePath,
		Expires:  now.Add(ttl),
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}, nil
}

func (i CookieIssuer) Validate(cookieValue string, ip string, domain string) (*Payload, error) {
	parts := strings.Split(cookieValue, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, ErrCookieMalformed
	}

	if !signing.Verify(i.Key, parts[0], parts[1]) {
		return nil, ErrCookieInvalid
	}

	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: payload base64", ErrCookieMalformed)
	}

	var payload Payload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return nil, fmt.Errorf("%w: payload json", ErrCookieMalformed)
	}

	if payload.ExpiresAt <= i.now().Unix() {
		return nil, ErrCookieExpired
	}
	if payload.IPHash != trust.HashIP(ip) {
		return nil, ErrCookieIPMismatch
	}
	if payload.Domain != domain {
		return nil, ErrCookieDomainMismatch
	}

	return &payload, nil
}

func (i CookieIssuer) signPayload(payload Payload) (string, error) {
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(rawPayload)
	return encodedPayload + "." + signing.Sign(i.Key, encodedPayload), nil
}

func (i CookieIssuer) now() time.Time {
	if i.Now == nil {
		return time.Now()
	}
	return i.Now()
}

func fingerprintHash(value string) string {
	if len(value) == 64 {
		return strings.ToLower(value)
	}
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func clamp(value int, minValue int, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
