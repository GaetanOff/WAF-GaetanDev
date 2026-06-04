package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

const HeadlessRendererDelta = -30

var (
	ErrInvalidFingerprint = errors.New("invalid fingerprint")
	ErrHeadlessRenderer   = errors.New("headless webgl renderer")
	screenPattern         = regexp.MustCompile(`^\d+x\d+x\d+$`)
)

type Fingerprint struct {
	UA            string `json:"ua"`
	TZ            int    `json:"tz"`
	Lang          string `json:"lang"`
	Screen        string `json:"screen"`
	CPU           int    `json:"cpu"`
	Touch         int    `json:"touch"`
	CanvasHash    string `json:"canvas_hash"`
	WebGLRenderer string `json:"webgl_renderer"`
	Plugins       int    `json:"plugins"`
}

func Parse(fp Fingerprint) (Fingerprint, error) {
	if strings.TrimSpace(fp.UA) == "" ||
		strings.TrimSpace(fp.Lang) == "" ||
		strings.TrimSpace(fp.Screen) == "" ||
		strings.TrimSpace(fp.CanvasHash) == "" ||
		strings.TrimSpace(fp.WebGLRenderer) == "" {
		return Fingerprint{}, ErrInvalidFingerprint
	}
	if !screenPattern.MatchString(fp.Screen) {
		return Fingerprint{}, ErrInvalidFingerprint
	}
	if fp.CPU < 1 || fp.CPU > 256 || fp.Touch < 0 || fp.Plugins < 0 {
		return Fingerprint{}, ErrInvalidFingerprint
	}
	if len(fp.CanvasHash) != 64 {
		return Fingerprint{}, ErrInvalidFingerprint
	}
	canvasHash := strings.ToLower(fp.CanvasHash)
	if _, err := hex.DecodeString(canvasHash); err != nil {
		return Fingerprint{}, ErrInvalidFingerprint
	}
	fp.CanvasHash = canvasHash

	if IsHeadlessRenderer(fp.WebGLRenderer) {
		return fp, ErrHeadlessRenderer
	}

	return fp, nil
}

func Hash(fp Fingerprint) string {
	raw, _ := json.Marshal(fp)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func IsHeadlessRenderer(renderer string) bool {
	normalized := strings.ToLower(renderer)
	return strings.Contains(normalized, "swiftshader") ||
		strings.Contains(normalized, "llvmpipe") ||
		strings.Contains(normalized, "mesa/x.org")
}
