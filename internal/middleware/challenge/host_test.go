package challenge

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Le cookie de clearance est signé pour l'hôte normalisé, comme la décision de
// challenge par domaine (FR-06) : un visiteur dont le Host varie en casse ou
// porte le port ne doit pas perdre sa clearance.
func TestClearanceCookieHoldsAcrossHostSpellings(t *testing.T) {
	middleware, store := newTestChallengeMiddleware(t)
	defer store.Close()
	cookie, err := middleware.cookieIssuer.Issue("3.3.3.3", "example.test", strings.Repeat("a", 64), 75, time.Hour)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	for _, host := range []string{"example.test", "Example.TEST", "example.test:443"} {
		request := httptest.NewRequest(http.MethodGet, "http://example.test/page", nil)
		request.Host = host
		request.RemoteAddr = "3.3.3.3:1234"
		request.Header.Set("Accept", "text/html")
		request.AddCookie(&cookie)
		reached := false

		middleware.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			reached = true
		})).ServeHTTP(httptest.NewRecorder(), request)

		if !reached {
			t.Errorf("Host %q: a valid clearance cookie for example.test was challenged again", host)
		}
	}
}
