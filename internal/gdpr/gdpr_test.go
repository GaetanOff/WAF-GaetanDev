package gdpr

import "testing"

func TestAnonymizeIPv4ToSlash24(t *testing.T) {
	if got := AnonymizeIP("203.0.113.42"); got != "203.0.113.0" {
		t.Fatalf("AnonymizeIP(IPv4) = %q, want 203.0.113.0", got)
	}
}

func TestAnonymizeIPv6ToSlash48(t *testing.T) {
	got := AnonymizeIP("2001:db8:abcd:1234::1")
	if got != "2001:db8:abcd::" {
		t.Fatalf("AnonymizeIP(IPv6) = %q, want 2001:db8:abcd::", got)
	}
}

func TestAnonymizeInvalidIPUnchanged(t *testing.T) {
	if got := AnonymizeIP("not-an-ip"); got != "not-an-ip" {
		t.Fatalf("AnonymizeIP(invalid) = %q, want unchanged", got)
	}
}
