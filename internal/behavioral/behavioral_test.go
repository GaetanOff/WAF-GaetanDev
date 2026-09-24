package behavioral

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/trust"
)

func recordsFrom(paths []string, interval time.Duration) []record {
	base := time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC)
	records := make([]record, 0, len(paths))
	for i, p := range paths {
		records = append(records, record{path: p, at: base.Add(time.Duration(i) * interval)})
	}
	return records
}

func TestComputeAnomalyBelowMinRecordsIsZero(t *testing.T) {
	if got := computeAnomaly(recordsFrom([]string{"/a", "/b"}, time.Second)); got != 0 {
		t.Fatalf("anomaly = %d, want 0 (insufficient records)", got)
	}
}

func TestComputeAnomalyDetectsTimeUniformity(t *testing.T) {
	// Intervalles parfaitement réguliers (1s) + chemins variés.
	records := recordsFrom([]string{"/a", "/b", "/c", "/d", "/e", "/f"}, time.Second)
	if got := computeAnomaly(records); got < contribTimeUniformity {
		t.Fatalf("anomaly = %d, want >= %d (uniform timing)", got, contribTimeUniformity)
	}
}

func TestComputeAnomalyDetectsPathRepetition(t *testing.T) {
	paths := make([]string, 0, 15)
	for range 15 {
		paths = append(paths, "/same")
	}
	// Intervalles irréguliers pour isoler le signal de répétition.
	records := recordsFrom(paths, time.Second)
	for i := range records {
		records[i].at = records[i].at.Add(time.Duration(i*i) * time.Millisecond)
	}
	if got := computeAnomaly(records); got < contribPathRepetition {
		t.Fatalf("anomaly = %d, want >= %d (path repetition)", got, contribPathRepetition)
	}
}

func TestComputeAnomalyDetectsHighVelocity(t *testing.T) {
	paths := make([]string, 0, 25)
	for i := range 25 {
		paths = append(paths, fmt.Sprintf("/p%02d", i))
	}
	records := recordsFrom(paths, 100*time.Millisecond) // 25 paths en 2.4s
	if got := computeAnomaly(records); got < contribVelocity {
		t.Fatalf("anomaly = %d, want >= %d (high velocity)", got, contribVelocity)
	}
}

func TestComputeAnomalyDetectsAssetAbsence(t *testing.T) {
	records := recordsFrom([]string{"/a", "/b", "/c", "/d", "/e"}, 7*time.Second)
	if !isAssetAbsent(records) {
		t.Fatal("expected asset absence for HTML-only navigation")
	}
}

func TestComputeAnomalyHumanLikeIsLow(t *testing.T) {
	// Navigation humaine : intervalles irréguliers, assets présents.
	records := []record{
		{path: "/", at: time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC)},
		{path: "/style.css", at: time.Date(2126, 1, 1, 0, 0, 1, 0, time.UTC)},
		{path: "/app.js", at: time.Date(2126, 1, 1, 0, 0, 1, 200, time.UTC)},
		{path: "/articles", at: time.Date(2126, 1, 1, 0, 0, 9, 0, time.UTC)},
		{path: "/logo.png", at: time.Date(2126, 1, 1, 0, 0, 9, 300, time.UTC)},
		{path: "/articles/42", at: time.Date(2126, 1, 1, 0, 0, 25, 0, time.UTC)},
	}
	if got := computeAnomaly(records); got >= contribTimeUniformity {
		t.Fatalf("anomaly = %d, want low for human-like navigation", got)
	}
}

func TestHandlerPublishesBehavioralScoreFromPreviousRequests(t *testing.T) {
	tracker := New(50)
	defer tracker.Close()

	ipHash := trust.HashIP("1.2.3.4")
	// Pré-remplit le buffer avec un motif uniforme via ingestion synchrone.
	base := time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 6 {
		tracker.ingest(event{ipHash: ipHash, path: fmt.Sprintf("/p%d", i), at: base.Add(time.Duration(i) * time.Second)})
	}
	if tracker.Score(ipHash) == 0 {
		t.Fatal("expected non-zero anomaly score after uniform ingestion")
	}

	var published string
	request := httptest.NewRequest(http.MethodGet, "http://example.test/next", nil)
	request.RemoteAddr = "1.2.3.4:1234"
	tracker.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		published = r.Header.Get("X-WAF-Risk-behavioral")
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), request)

	if published == "" {
		t.Fatal("X-WAF-Risk-behavioral not published from previous-request score")
	}
}

func TestHandlerSkipsWhenPassMarked(t *testing.T) {
	tracker := New(50)
	defer tracker.Close()
	request := httptest.NewRequest(http.MethodGet, "http://example.test/x", nil)
	request.RemoteAddr = "1.2.3.4:1234"
	request.Header.Set("X-WAF-Action", "PASS")

	tracker.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-WAF-Risk-behavioral") != "" {
			t.Fatal("PASS request must not be analyzed")
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(httptest.NewRecorder(), request)
}

// Régression : le bypass FR-24 marque les assets PASS en amont. Ils doivent
// quand même compter pour le signal d'absence d'assets, sinon tout humain qui
// visite 5 pages est classé headless.
func TestHandlerRecordsStaticAssetsMarkedPass(t *testing.T) {
	tracker := New(50)
	defer tracker.Close()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := tracker.Handler(next)

	serve := func(path string, staticAsset bool) {
		request := httptest.NewRequest(http.MethodGet, "http://example.test"+path, nil)
		request.RemoteAddr = "1.2.3.4:1234"
		if staticAsset {
			request.Header.Set("X-WAF-Action", "PASS")
			request.Header.Set("X-WAF-Reason", "static_asset")
		}
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}
	for i := range 6 {
		serve(fmt.Sprintf("/page-%d", i), false)
		serve(fmt.Sprintf("/assets/app-%d.webp", i), true) // extension hors isAssetPath
	}

	ipHash := trust.HashIP("1.2.3.4")
	deadline := time.Now().Add(2 * time.Second)
	for {
		tracker.mu.RLock()
		recorded := len(tracker.buffers[ipHash])
		tracker.mu.RUnlock()
		if recorded == 12 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	tracker.mu.RLock()
	buffer := append([]record(nil), tracker.buffers[ipHash]...)
	tracker.mu.RUnlock()
	if isAssetAbsent(buffer) {
		t.Fatalf("assets marked PASS were not recorded (buffer=%d records)", len(buffer))
	}
}

func TestComputeAnomalyIgnoresAssetBurstsForNavigationSignals(t *testing.T) {
	base := time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC)
	var records []record
	pageTimes := []time.Duration{0, 7 * time.Second, 19 * time.Second, 26 * time.Second, 41 * time.Second, 53 * time.Second}
	for i, at := range pageTimes {
		records = append(records, record{path: fmt.Sprintf("/articles/%d", 10-i), at: base.Add(at)})
		// Rafale de 20 sous-requêtes en quelques millisecondes : un chargement de page.
		for j := range 20 {
			records = append(records, record{path: fmt.Sprintf("/static/%c%d", 'a'+j, i), at: base.Add(at + time.Duration(j)*time.Millisecond), asset: true})
		}
	}
	if got := computeAnomaly(records); got != 0 {
		t.Fatalf("anomaly = %d, want 0 for a human loading pages with their assets", got)
	}
}
