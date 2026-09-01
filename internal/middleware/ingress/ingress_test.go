package ingress_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gaetandev/waf/internal/middleware/ingress"
)

func TestMiddlewareStripsClientSuppliedWAFHeaders(t *testing.T) {
	// Un client qui forge X-WAF-Action: PASS contournerait challenge, rate
	// limiting, intégrité, threat intel et moteur de règles.
	forged := []string{
		"X-WAF-Action",
		"x-waf-action",
		"X-WAF-Score",
		"X-WAF-Score-Delta",
		"X-WAF-Reason",
		"X-WAF-Risk-Decision",
		"X-WAF-Under-Attack-Enforce",
		"X-WAF-Origin-Token",
	}

	for _, name := range forged {
		t.Run(name, func(t *testing.T) {
			var seen string
			handler := ingress.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				seen = r.Header.Get(name)
			}))

			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.Header.Set(name, "PASS")
			handler.ServeHTTP(httptest.NewRecorder(), request)

			if seen != "" {
				t.Fatalf("en-tête %s fourni par le client non supprimé: %q", name, seen)
			}
		})
	}
}

func TestMiddlewarePreservesUnrelatedHeaders(t *testing.T) {
	var host, auth, cfIP string
	handler := ingress.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		host = r.Header.Get("X-Forwarded-Host")
		auth = r.Header.Get("Authorization")
		cfIP = r.Header.Get("CF-Connecting-IP")
	}))

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Forwarded-Host", "panel.example.com")
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("CF-Connecting-IP", "203.0.113.7")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	if host != "panel.example.com" || auth != "Bearer token" || cfIP != "203.0.113.7" {
		t.Fatalf("en-têtes légitimes altérés: host=%q auth=%q cf=%q", host, auth, cfIP)
	}
}

// http.Header.Set canonicalise la clé : les cas ci-dessus valident donc la
// canonicalisation autant que le filtre. Ce test écrit directement dans la map
// pour prouver que le filtre lui-même ignore la casse, sans dépendre d'un
// invariant interne de net/http.
func TestMiddlewareStripsNonCanonicalHeaderKeys(t *testing.T) {
	var seen []string
	handler := ingress.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		for name := range r.Header {
			seen = append(seen, name)
		}
	}))

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header["x-waf-action"] = []string{"PASS"}
	request.Header["X-WAF-SCORE"] = []string{"100"}
	request.Header["x-WaF-Risk-Geo"] = []string{"0"}
	handler.ServeHTTP(httptest.NewRecorder(), request)

	if len(seen) != 0 {
		t.Fatalf("en-têtes non canoniques conservés: %v", seen)
	}
}

// Un en-tête multivalué doit disparaître entièrement : supprimer la seule
// première valeur laisserait le pipeline lire une valeur d'origine cliente.
func TestMiddlewareStripsEveryValueOfARepeatedHeader(t *testing.T) {
	var values []string
	handler := ingress.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		values = r.Header.Values("X-WAF-Action")
	}))

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Add("X-WAF-Action", "BLOCK")
	request.Header.Add("X-WAF-Action", "PASS")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	if len(values) != 0 {
		t.Fatalf("valeurs conservées pour X-WAF-Action: %v", values)
	}
}

// Le préfixe ne doit pas déborder sur des en-têtes voisins qui ne sont pas de
// l'état interne : "X-WAF" nu et "X-WAFER-*" ne sont pas des en-têtes du WAF.
func TestMiddlewarePreservesHeadersOutsideThePrefix(t *testing.T) {
	var bare, neighbour string
	handler := ingress.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		bare = r.Header.Get("X-WAF")
		neighbour = r.Header.Get("X-WAFER-Flavour")
	}))

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-WAF", "nu")
	request.Header.Set("X-WAFER-Flavour", "vanille")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	if bare != "nu" || neighbour != "vanille" {
		t.Fatalf("en-têtes hors préfixe altérés: X-WAF=%q X-WAFER-Flavour=%q", bare, neighbour)
	}
}
