package admin

import "testing"

func TestBearerMatches(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{"exact", "Bearer " + token, true},
		{"missing", "", false},
		{"token without scheme", token, false},
		{"prefix of the token", "Bearer " + token[:31], false},
		{"token with a suffix", "Bearer " + token + "x", false},
		{"other scheme", "Basic " + token, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := bearerMatches(tc.header, token); got != tc.want {
				t.Fatalf("bearerMatches(%q) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}
