package origin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTokenRotatesHourlyAndVerifiesWithinTolerance(t *testing.T) {
	signer := NewSigner("origin-secret-key-min-16")
	base := time.Date(2126, 1, 1, 12, 30, 0, 0, time.UTC)
	signer.now = func() time.Time { return base }

	token := signer.Token("example.com")
	if !signer.Verify("example.com", token) {
		t.Fatal("current token must verify")
	}

	// 2 h plus tard : le token initial reste accepté (tolérance 2h).
	signer.now = func() time.Time { return base.Add(2 * time.Hour) }
	if !signer.Verify("example.com", token) {
		t.Fatal("token within 2h tolerance must verify")
	}

	// 3 h plus tard : hors tolérance → rejeté.
	signer.now = func() time.Time { return base.Add(3 * time.Hour) }
	if signer.Verify("example.com", token) {
		t.Fatal("token beyond tolerance must be rejected")
	}
}

func TestTokenIsDomainSpecific(t *testing.T) {
	signer := NewSigner("origin-secret-key-min-16")
	token := signer.Token("a.example.com")
	if signer.Verify("b.example.com", token) {
		t.Fatal("token for one domain must not verify for another")
	}
}

func TestInjectorSetsHeaderForUpstream(t *testing.T) {
	signer := NewSigner("origin-secret-key-min-16")
	var forwarded string
	request := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	signer.Injector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Get(HeaderToken)
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), request)

	if forwarded == "" || !signer.Verify("example.com", forwarded) {
		t.Fatalf("injected token %q must verify for the request host", forwarded)
	}
}

func TestVerifyHandler(t *testing.T) {
	signer := NewSigner("origin-secret-key-min-16")
	token := signer.Token("example.com")

	valid := httptest.NewRequest(http.MethodGet, "http://waf/waf/origin/verify?domain=example.com", nil)
	valid.Header.Set(HeaderToken, token)
	vr := httptest.NewRecorder()
	signer.VerifyHandler(vr, valid)
	if vr.Code != http.StatusOK {
		t.Fatalf("valid token status = %d, want 200", vr.Code)
	}

	bad := httptest.NewRequest(http.MethodGet, "http://waf/waf/origin/verify?domain=example.com", nil)
	bad.Header.Set(HeaderToken, "forged")
	br := httptest.NewRecorder()
	signer.VerifyHandler(br, bad)
	if br.Code != http.StatusUnauthorized {
		t.Fatalf("forged token status = %d, want 401", br.Code)
	}
}

// FR-19 × FR-30 : le token capturé avant l'assainissement d'ingress reste lisible
// par VerifyHandler alors qu'il a disparu des en-têtes de la requête.
func TestVerifyHandlerReadsTheCapturedTokenAfterHeaderRemoval(t *testing.T) {
	signer := NewSigner("origin-secret-key-min-16")
	token := signer.Token("example.com")

	// L'assainisseur tourne entre la capture et le handler, comme dans routes().
	stripper := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Del(HeaderToken)
			next.ServeHTTP(w, r)
		})
	}
	handler := CaptureInboundToken(stripper(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(HeaderToken); got != "" {
			t.Fatalf("le token ne doit pas être réinjecté dans r.Header, trouvé %q", got)
		}
		signer.VerifyHandler(w, r)
	})))

	request := httptest.NewRequest(http.MethodGet, "http://waf/waf/origin/verify?domain=example.com", nil)
	request.Header.Set(HeaderToken, token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 : le token capturé doit rester vérifiable", response.Code)
	}
}

// La capture ne relâche rien : un token forgé reste refusé, elle ne porte que sur
// la lisibilité de la valeur, pas sur sa validité.
func TestCaptureInboundTokenDoesNotWeakenVerification(t *testing.T) {
	signer := NewSigner("origin-secret-key-min-16")
	handler := CaptureInboundToken(http.HandlerFunc(signer.VerifyHandler))

	request := httptest.NewRequest(http.MethodGet, "http://waf/waf/origin/verify?domain=example.com", nil)
	request.Header.Set(HeaderToken, "forged")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 pour un token forgé", response.Code)
	}
}

// Sans en-tête entrant, la capture ne doit pas placer de valeur vide dans le
// contexte : le handler doit répondre 401, pas paniquer ni accepter.
func TestCaptureInboundTokenWithoutHeader(t *testing.T) {
	signer := NewSigner("origin-secret-key-min-16")
	handler := CaptureInboundToken(http.HandlerFunc(signer.VerifyHandler))

	request := httptest.NewRequest(http.MethodGet, "http://waf/waf/origin/verify?domain=example.com", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 sans token", response.Code)
	}
}
