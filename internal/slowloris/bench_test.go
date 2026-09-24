package slowloris

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
)

// Charge multi-cœurs, IP distinctes : mesure la contention du verrou.
func BenchmarkLimiterParallel(b *testing.B) {
	limiter := New(100)
	handler := limiter.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	var next atomic.Int64
	b.RunParallel(func(pb *testing.PB) {
		request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
		request.RemoteAddr = "10.0." + strconv.Itoa(int(next.Add(1))%250) + ".1:1234"
		recorder := httptest.NewRecorder()
		for pb.Next() {
			handler.ServeHTTP(recorder, request)
		}
	})
}
