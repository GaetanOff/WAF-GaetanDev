package ipkey

import "testing"

func TestSubject(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7":                    "203.0.113.7",
		"::ffff:203.0.113.7":             "203.0.113.7",
		"2001:db8:1:2:3:4:5:6":           "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff:ffff:ffff:ff": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":                "2001:db8:1:3::/64",
		"fe80::1%eth0":                   "fe80::/64",
		"not-an-ip":                      "not-an-ip",
		"":                               "",
	}
	for ip, want := range cases {
		if got := Subject(ip); got != want {
			t.Errorf("Subject(%q) = %q, want %q", ip, got, want)
		}
	}
}

// Deux adresses d'un même /64 sont un seul client ; deux /64 voisins, deux.
func TestSubjectAggregatesIPv6Per64(t *testing.T) {
	if Subject("2001:db8:1:2::1") != Subject("2001:db8:1:2:dead:beef:0:1") {
		t.Fatal("addresses of one /64 must share an identity")
	}
	if Subject("2001:db8:1:2::1") == Subject("2001:db8:1:3::1") {
		t.Fatal("distinct /64 prefixes must not share an identity")
	}
}
