package hostname

import "testing"

func TestDeclaredLabel(t *testing.T) {
	declared := NewDeclared([]string{"Example.com", "*.shop.test"})
	for host, want := range map[string]string{
		"example.com:443": "example.com",
		"a.shop.test":     "*.shop.test",
		"shop.test":       "*.shop.test",
		"evil.test":       Undeclared,
	} {
		if got := declared.Label(host); got != want {
			t.Errorf("Label(%q) = %q, want %q", host, got, want)
		}
	}
	if got := (Declared{}).Label("example.com"); got != Undeclared {
		t.Errorf("zero Declared: Label = %q, want %q", got, Undeclared)
	}
}
