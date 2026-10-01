package recovery

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func panicking(value any) http.Handler {
	return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(value)
	})
}

// captureLogs redirige slog vers un tampon le temps du test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

// reverse-proxy.feature — « Panic d'un middleware — 500 journalisé et compté ».
func TestPanicIsLoggedCountedAndAnswered500(t *testing.T) {
	logs := captureLogs(t)
	panics := 0
	response := httptest.NewRecorder()
	response.Header().Set(requestIDHeader, "req-123")

	Middleware(panicking("nil map"), func() { panics++ }, PlainText).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", response.Code)
	}
	if panics != 1 {
		t.Fatalf("onPanic called %d times, want 1", panics)
	}
	for _, want := range []string{`"level":"ERROR"`, `"request_id":"req-123"`, `"path":"/boom"`, `"panic":"nil map"`, `"stack":"goroutine`} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("log = %s, want it to contain %s", logs.String(), want)
		}
	}
}

// Une réponse déjà entamée ne peut plus devenir un 500 : la connexion est
// interrompue (http.ErrAbortHandler) au lieu d'accoler un corps d'erreur.
func TestPanicAfterHeadersAbortsTheConnection(t *testing.T) {
	captureLogs(t)
	panics := 0
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("partial"))
		panic("late")
	}), func() { panics++ }, PlainText)

	defer func() {
		if err, ok := recover().(error); !ok || !errors.Is(err, http.ErrAbortHandler) {
			t.Fatalf("recovered = %v, want http.ErrAbortHandler", err)
		}
		if panics != 1 {
			t.Fatalf("onPanic called %d times, want 1", panics)
		}
	}()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

// http.ErrAbortHandler est un abandon voulu : ni journalisé, ni compté,
// propagé tel quel à net/http.
func TestAbortHandlerIsPropagatedUntouched(t *testing.T) {
	logs := captureLogs(t)
	panics := 0
	defer func() {
		recovered := recover()
		if err, ok := recovered.(error); !ok || !errors.Is(err, http.ErrAbortHandler) {
			t.Fatalf("recovered = %v, want http.ErrAbortHandler", recovered)
		}
		if panics != 0 || logs.Len() != 0 {
			t.Fatalf("abort counted %d times and logged %q, want neither", panics, logs.String())
		}
	}()
	Middleware(panicking(http.ErrAbortHandler), func() { panics++ }, PlainText).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

func TestNoPanicPassesThrough(t *testing.T) {
	response := httptest.NewRecorder()
	Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), func() { t.Fatal("onPanic called without panic") }, PlainText).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}

// Le WebSocket et le streaming passent par http.ResponseController, qui
// retrouve le writer d'origine via Unwrap.
func TestTrackerUnwrapsToTheOriginalWriter(t *testing.T) {
	response := httptest.NewRecorder()
	Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Fatalf("Flush through the tracker: %v", err)
		}
	}), nil, PlainText).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	if !response.Flushed {
		t.Fatal("the original writer was not flushed")
	}
}
