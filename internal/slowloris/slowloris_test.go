package slowloris

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func requestFrom(ip string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	r.RemoteAddr = ip + ":1234"
	return r
}

func TestLimiterReleasesAfterRequest(t *testing.T) {
	limiter := New(1)
	handler := limiter.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	// Requêtes séquentielles : chacune libère le slot → toutes passent.
	for i := range 3 {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, requestFrom("1.2.3.4"))
		if response.Code != http.StatusNoContent {
			t.Fatalf("sequential request %d status = %d, want 204", i, response.Code)
		}
	}
}

func TestLimiterRejectsConcurrentOverLimit(t *testing.T) {
	limiter := New(1)
	release := make(chan struct{})
	entered := make(chan struct{})
	handler := limiter.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))

	var wg sync.WaitGroup
	wg.Go(func() {
		handler.ServeHTTP(httptest.NewRecorder(), requestFrom("1.2.3.4"))
	})
	<-entered // la 1re requête occupe le slot

	// 2e requête concurrente même IP → rejetée (429).
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, requestFrom("1.2.3.4"))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("concurrent over-limit status = %d, want 429", second.Code)
	}

	close(release)
	wg.Wait()
}

func TestLimiterIsPerIP(t *testing.T) {
	limiter := New(1)
	release := make(chan struct{})
	entered := make(chan struct{})
	handler := limiter.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))

	go handler.ServeHTTP(httptest.NewRecorder(), requestFrom("1.1.1.1"))
	<-entered

	// IP différente → pas affectée par le slot de 1.1.1.1.
	other := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(other, requestFrom("2.2.2.2"))
		close(done)
	}()
	<-entered // la requête de 2.2.2.2 entre aussi
	close(release)
	<-done
}
