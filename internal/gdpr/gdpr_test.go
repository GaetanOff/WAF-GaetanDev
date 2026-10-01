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

// Une IPv4 mappée se tronque comme une IPv4, une IPv6 zonée sans sa zone :
// net.ParseIP refusait la zone et l'adresse était journalisée entière.
func TestAnonymizeMappedAndZonedAddresses(t *testing.T) {
	for ip, want := range map[string]string{
		"::ffff:203.0.113.42":      "203.0.113.0",
		"fe80::1234:5678:9abc%en0": "fe80::",
	} {
		if got := AnonymizeIP(ip); got != want {
			t.Errorf("AnonymizeIP(%q) = %q, want %q", ip, got, want)
		}
	}
}
