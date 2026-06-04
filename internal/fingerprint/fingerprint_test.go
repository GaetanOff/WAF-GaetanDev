package fingerprint

import (
	"errors"
	"testing"
)

func TestParseValidFingerprintAndHash(t *testing.T) {
	fp, err := Parse(validFingerprint())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	hash := Hash(fp)
	if len(hash) != 64 {
		t.Fatalf("hash len = %d, want 64", len(hash))
	}
}

func TestParseRejectsInvalidCanvasHash(t *testing.T) {
	fp := validFingerprint()
	fp.CanvasHash = "not-hex"

	_, err := Parse(fp)
	if !errors.Is(err, ErrInvalidFingerprint) {
		t.Fatalf("Parse() error = %v, want ErrInvalidFingerprint", err)
	}
}

func TestParseDetectsHeadlessRenderers(t *testing.T) {
	renderers := []string{
		"Google SwiftShader",
		"ANGLE (Default, SwiftShader)",
		"llvmpipe (LLVM 15.0.7, 256 bits)",
		"Mesa/X.org",
	}

	for _, renderer := range renderers {
		t.Run(renderer, func(t *testing.T) {
			fp := validFingerprint()
			fp.WebGLRenderer = renderer

			_, err := Parse(fp)
			if !errors.Is(err, ErrHeadlessRenderer) {
				t.Fatalf("Parse() error = %v, want ErrHeadlessRenderer", err)
			}
		})
	}
}

func validFingerprint() Fingerprint {
	return Fingerprint{
		UA:            "Mozilla/5.0",
		TZ:            0,
		Lang:          "en-US",
		Screen:        "1920x1080x24",
		CPU:           4,
		Touch:         0,
		CanvasHash:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		WebGLRenderer: "ANGLE",
		Plugins:       3,
	}
}
