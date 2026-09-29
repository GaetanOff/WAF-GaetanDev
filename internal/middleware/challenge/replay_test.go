package challenge

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/gaetandev/waf/internal/trust"
)

// FR-30 : un token accepté une fois est refusé en token_already_used, sans
// nouveau bonus de score.
func TestMiddlewareVerifyRejectsReplayedToken(t *testing.T) {
	middleware, store := newTestChallengeMiddleware(t)
	defer store.Close()
	middleware.scores.Set("3.3.3.3", "example.test", 35)
	token, err := middleware.tokenIssuer.GenerateForRedirect("3.3.3.3", "example.test", "/page")
	if err != nil {
		t.Fatalf("GenerateForRedirect() error = %v", err)
	}
	body := submissionJSON(token, solvePow(t, token, middleware.staticDifficulty()), 1200)
	handler := middleware.Handler(http.NotFoundHandler())

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, verifyRequest(t, "3.3.3.3:1234", body))
	if first.Code != http.StatusOK {
		t.Fatalf("first submission = %d %s, want 200", first.Code, first.Body.String())
	}
	replay := httptest.NewRecorder()
	handler.ServeHTTP(replay, verifyRequest(t, "3.3.3.3:1234", body))

	if replay.Code != http.StatusBadRequest || !strings.Contains(replay.Body.String(), `"token_already_used"`) {
		t.Fatalf("replay = %d %s, want 400 token_already_used", replay.Code, replay.Body.String())
	}
	if got := replay.Header().Get(headerReason); got != "verify_token_already_used" {
		t.Fatalf("X-WAF-Reason = %q, want verify_token_already_used", got)
	}
	if len(replay.Result().Cookies()) != 0 {
		t.Fatal("a replayed token must not issue a clearance cookie")
	}
	visitor, _ := store.GetVisitor(trust.HashIP("3.3.3.3"))
	if visitor.Score != 60 {
		t.Fatalf("score = %d, want 60 (one bonus only)", visitor.Score)
	}
}

// Une soumission rejetée (PoW fausse) ne consomme pas le token : la bonne
// soumission qui suit passe.
func TestMiddlewareVerifyRejectionDoesNotBurnTheToken(t *testing.T) {
	middleware, store := newTestChallengeMiddleware(t)
	defer store.Close()
	token, err := middleware.tokenIssuer.Generate("3.3.3.3", "example.test")
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	handler := middleware.Handler(http.NotFoundHandler())
	failed := httptest.NewRecorder()
	handler.ServeHTTP(failed, verifyRequest(t, "3.3.3.3:1234", submissionJSON(token, failPow(t, token, middleware.staticDifficulty()), 1200)))
	if failed.Code != http.StatusBadRequest {
		t.Fatalf("invalid pow = %d, want 400", failed.Code)
	}
	solved := httptest.NewRecorder()
	handler.ServeHTTP(solved, verifyRequest(t, "3.3.3.3:1234", submissionJSON(token, solvePow(t, token, middleware.staticDifficulty()), 1200)))
	if solved.Code != http.StatusOK {
		t.Fatalf("valid submission after a rejection = %d %s, want 200", solved.Code, solved.Body.String())
	}
}

func TestUsedTokensConcurrentConsumeAcceptsOnce(t *testing.T) {
	used := newUsedTokens(maxUsedTokens)
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for range 32 {
		wg.Go(func() {
			if !used.consume("payload.signature", 130, 100) {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("accepted = %d, want 1", accepted)
	}
}

func TestUsedTokensForgetsExpiredTokens(t *testing.T) {
	used := newUsedTokens(2)
	if used.consume("a.sig-a", 110, 100) || used.consume("b.sig-b", 110, 100) {
		t.Fatal("first use reported as a replay")
	}
	if !used.consume("a.sig-a", 110, 105) {
		t.Fatal("replay before expiry accepted")
	}
	// Pleine : un nouveau token passe sans être retenu tant que rien n'expire.
	if used.consume("c.sig-c", 110, 105) || used.consume("c.sig-c", 110, 105) {
		t.Fatal("saturated memory must let submissions through")
	}
	// Après expiration, la purge libère la place.
	if used.consume("d.sig-d", 130, 111) {
		t.Fatal("new token reported as a replay")
	}
	if !used.consume("d.sig-d", 130, 112) {
		t.Fatal("token remembered after the purge must be refused on replay")
	}
	if len(used.expiresAt) != 1 {
		t.Fatalf("entries = %d, want 1 after the purge", len(used.expiresAt))
	}
}

// Chaque code d'erreur de /waf/verify est déclaré dans l'enum VerifyError de
// public.openapi.yaml : un code ajouté au code sans le contrat est un
// changement silencieux de l'API publique.
func TestVerifyErrorCodesAreInTheContract(t *testing.T) {
	source, err := os.ReadFile("middleware.go")
	if err != nil {
		t.Fatalf("read middleware.go: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "specs", "api", "public.openapi.yaml"))
	if err != nil {
		t.Fatalf("read public.openapi.yaml: %v", err)
	}
	var contract struct {
		Components struct {
			Schemas struct {
				VerifyError struct {
					Properties struct {
						Error struct {
							Enum []string `yaml:"enum"`
						} `yaml:"error"`
					} `yaml:"properties"`
				} `yaml:"VerifyError"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &contract); err != nil {
		t.Fatalf("parse public.openapi.yaml: %v", err)
	}
	declared := contract.Components.Schemas.VerifyError.Properties.Error.Enum
	codes := regexp.MustCompile(`(?:rejectSubmission\(w|writeError\(w, http\.Status\w+), "([a-z_]+)"\)`).FindAllSubmatch(source, -1)
	if len(codes) == 0 {
		t.Fatal("no verify error code found in middleware.go")
	}
	for _, code := range codes {
		if !slices.Contains(declared, string(code[1])) {
			t.Errorf("verify error %q is returned but absent from VerifyError", code[1])
		}
	}
}
