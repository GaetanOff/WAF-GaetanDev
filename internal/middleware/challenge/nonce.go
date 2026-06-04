package challenge

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gaetandev/waf/internal/signing"
	"github.com/gaetandev/waf/internal/trust"
)

var (
	ErrTokenMalformed      = errors.New("token malformed")
	ErrTokenInvalid        = errors.New("token invalid")
	ErrTokenExpired        = errors.New("token expired")
	ErrTokenIPMismatch     = errors.New("token ip mismatch")
	ErrTokenDomainMismatch = errors.New("token domain mismatch")
)

type TokenIssuer struct {
	Key []byte
	TTL time.Duration
	Now func() time.Time
}

type TokenPayload struct {
	IPHash    string `json:"ip_hash"`
	Domain    string `json:"domain"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

func NewTokenIssuer(key string, ttl time.Duration) TokenIssuer {
	return TokenIssuer{
		Key: []byte(key),
		TTL: ttl,
		Now: time.Now,
	}
}

func GenerateToken(ip string, domain string, key string, ttl time.Duration) (string, error) {
	return NewTokenIssuer(key, ttl).Generate(ip, domain)
}

func ValidateToken(token string, ip string, domain string, key string) (*TokenPayload, error) {
	return NewTokenIssuer(key, 0).Validate(token, ip, domain)
}

func (i TokenIssuer) Generate(ip string, domain string) (string, error) {
	now := i.now()
	payload := TokenPayload{
		IPHash:    trust.HashIP(ip),
		Domain:    domain,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(i.TTL).Unix(),
	}

	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(rawPayload)
	return encodedPayload + "." + signing.Sign(i.Key, encodedPayload), nil
}

func (i TokenIssuer) Validate(token string, ip string, domain string) (*TokenPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, ErrTokenMalformed
	}
	if !signing.Verify(i.Key, parts[0], parts[1]) {
		return nil, ErrTokenInvalid
	}

	rawPayload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: payload base64", ErrTokenMalformed)
	}

	var payload TokenPayload
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return nil, fmt.Errorf("%w: payload json", ErrTokenMalformed)
	}

	if payload.ExpiresAt <= i.now().Unix() {
		return nil, ErrTokenExpired
	}
	if payload.IPHash != trust.HashIP(ip) {
		return nil, ErrTokenIPMismatch
	}
	if payload.Domain != domain {
		return nil, ErrTokenDomainMismatch
	}

	return &payload, nil
}

func (i TokenIssuer) now() time.Time {
	if i.Now == nil {
		return time.Now()
	}
	return i.Now()
}
