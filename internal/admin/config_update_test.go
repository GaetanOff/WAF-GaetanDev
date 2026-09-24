package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gaetandev/waf/internal/config"
)

// Régression : PATCH /waf/admin/config vérifiait le nom des sections et
// journalisait « applied » sans transmettre aucune valeur au runtime.
func TestAdminPatchConfigAppliesValues(t *testing.T) {
	server := newTestServer(t)
	var applied *config.Config
	server.WithConfigApplier(func(next config.Config) { applied = &next })

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, requestWithAuth(http.MethodPatch, "/waf/admin/config",
		`{"rate_limit":{"requests_per_second":20,"burst":40},"trust":{"challenge_threshold":45}}`))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s, want 200", response.Code, response.Body.String())
	}
	if applied == nil || applied.RateLimit.RequestsPerSecond != 20 || applied.RateLimit.Burst != 40 || applied.Trust.ChallengeThreshold != 45 {
		t.Fatalf("applied config = %+v, want the patched values pushed to the runtime", applied)
	}
	var body struct {
		UpdatedFields []string `json:"updated_fields"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []string{"rate_limit.burst", "rate_limit.requests_per_second", "trust.challenge_threshold"}
	if len(body.UpdatedFields) != len(want) {
		t.Fatalf("updated_fields = %v, want %v", body.UpdatedFields, want)
	}
	for i := range want {
		if body.UpdatedFields[i] != want[i] {
			t.Fatalf("updated_fields = %v, want %v", body.UpdatedFields, want)
		}
	}
	if got := server.state.Config().RateLimit.Burst; got != 40 {
		t.Fatalf("GET config burst = %d, want 40 after PATCH", got)
	}
}

func TestAdminPatchConfigRejectsInvalidValues(t *testing.T) {
	server := newTestServer(t)
	called := false
	server.WithConfigApplier(func(config.Config) { called = true })
	before := server.state.Config().Trust.BlockThreshold

	for _, body := range []string{
		`{"trust":{"block_threshold":90}}`,          // block >= challenge
		`{"rate_limit":{"burst":0}}`,                // < 1
		`{"challenge":{"pow_difficulty":40}}`,       // hors [8..24]
		`{"rate_limit":{"requests_per_minute":10}}`, // champ non modifiable à chaud
		`{"upstream":{}}`,                           // section inconnue
		`{}`,                                        // rien à modifier
	} {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, requestWithAuth(http.MethodPatch, "/waf/admin/config", body))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", body, response.Code)
		}
	}
	if called {
		t.Fatal("an invalid update must not reach the runtime")
	}
	if got := server.state.Config().Trust.BlockThreshold; got != before {
		t.Fatalf("block_threshold = %d, want unchanged %d", got, before)
	}
}

func TestAdminPatchConfigWithoutApplierIsUnavailable(t *testing.T) {
	server := newTestServer(t)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, requestWithAuth(http.MethodPatch, "/waf/admin/config", `{"rate_limit":{"burst":40}}`))

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 rather than a silent no-op", response.Code)
	}
}
