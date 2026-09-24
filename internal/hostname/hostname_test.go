package hostname

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{host: "example.com", want: "example.com"},
		{host: "Example.COM", want: "example.com"},
		{host: "example.com:443", want: "example.com"},
		{host: "Example.com:8080", want: "example.com"},
		{host: " example.com ", want: "example.com"},
		{host: "[::1]:8443", want: "::1"},
		{host: "::1", want: "::1"},
		{host: "", want: ""},
	}
	for _, tt := range tests {
		if got := Normalize(tt.host); got != tt.want {
			t.Errorf("Normalize(%q) = %q, want %q", tt.host, got, tt.want)
		}
	}
}
