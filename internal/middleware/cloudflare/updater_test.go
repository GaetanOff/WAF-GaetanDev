package cloudflare

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	validIPv4List = "198.51.100.0/24\n203.0.113.0/24\n192.0.2.0/24\n100.64.0.0/10\n"
	validIPv6List = "2001:db8::/32\n2001:db8:1::/48\n2001:db8:2::/48\n2001:db8:3::/48\n"
)

// newTestUpdater sert deux listes depuis un serveur local et rend l'updater
// correspondant. La liste en vigueur est restaurée après le test : elle est
// globale au paquet, lue par IsCloudflareIP sur le chemin de requête.
func newTestUpdater(t *testing.T, ipv4Body string, ipv6Body string) (*Updater, *atomic.Int64) {
	t.Helper()
	t.Cleanup(resetRanges)

	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if strings.HasSuffix(r.URL.Path, "ips-v4") {
			_, _ = w.Write([]byte(ipv4Body))
			return
		}
		_, _ = w.Write([]byte(ipv6Body))
	}))
	t.Cleanup(server.Close)

	updater := NewUpdater(time.Hour,
		withEndpoints(server.URL+"/ips-v4", server.URL+"/ips-v6"),
		withClient(server.Client()),
	)
	return updater, &calls
}

func TestRefreshAdoptsValidatedLists(t *testing.T) {
	updater, calls := newTestUpdater(t, validIPv4List, validIPv6List)

	count, err := updater.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if count != 8 {
		t.Fatalf("count = %d, want 8", count)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("HTTP calls = %d, want 2 (one per family)", got)
	}
	if got := len(Ranges()); got != 8 {
		t.Fatalf("len(Ranges()) = %d, want 8", got)
	}
	// La liste récupérée remplace la liste compilée : une IP annoncée par la
	// nouvelle liste est reconnue...
	if !IsCloudflareIP(netip.MustParseAddr("198.51.100.7")) {
		t.Fatal("fetched range must be recognized as Cloudflare")
	}
	// ...et une IP de la seule liste compilée ne l'est plus.
	if IsCloudflareIP(netip.MustParseAddr("173.245.48.1")) {
		t.Fatal("builtin-only range must not be recognized once a list is adopted")
	}
}

func TestRefreshRejectsInvalidListsAndKeepsCurrentOne(t *testing.T) {
	cases := []struct {
		name     string
		ipv4Body string
		ipv6Body string
		wantErr  string
	}{
		{
			name:     "préfixe élargissant la confiance à tout Internet",
			ipv4Body: "0.0.0.0/0\n198.51.100.0/24\n203.0.113.0/24\n192.0.2.0/24\n",
			ipv6Body: validIPv6List,
			wantErr:  "wider than /8",
		},
		{
			name:     "préfixe IPv6 trop large",
			ipv4Body: validIPv4List,
			ipv6Body: "::/0\n2001:db8:1::/48\n2001:db8:2::/48\n2001:db8:3::/48\n",
			wantErr:  "wider than /19",
		},
		{
			name:     "page HTML au lieu d'une liste",
			ipv4Body: "<!doctype html><html><body>error</body></html>",
			ipv6Body: validIPv6List,
			wantErr:  "invalid prefix",
		},
		{
			name:     "liste vide",
			ipv4Body: validIPv4List,
			ipv6Body: "\n\n  \n",
			wantErr:  "no prefix found",
		},
		{
			name:     "liste tronquée",
			ipv4Body: "198.51.100.0/24\n203.0.113.0/24\n",
			ipv6Body: validIPv6List,
			wantErr:  "want at least 4",
		},
		{
			name:     "famille d'adresses incohérente avec la source",
			ipv4Body: validIPv6List,
			ipv6Body: validIPv6List,
			wantErr:  "expected address family",
		},
		{
			name:     "préfixe non canonique",
			ipv4Body: "198.51.100.1/24\n203.0.113.0/24\n192.0.2.0/24\n100.64.0.0/10\n",
			ipv6Body: validIPv6List,
			wantErr:  "not canonical",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			updater, _ := newTestUpdater(t, testCase.ipv4Body, testCase.ipv6Body)

			_, err := updater.Refresh(context.Background())
			if err == nil {
				t.Fatal("Refresh() error = nil, want a rejection")
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("error = %q, want it to mention %q", err, testCase.wantErr)
			}
			// La liste en vigueur reste la liste compilée : jamais de liste vide,
			// jamais d'adoption partielle.
			if len(Ranges()) != len(BuiltinRanges()) {
				t.Fatalf("len(Ranges()) = %d, want the builtin list (%d)", len(Ranges()), len(BuiltinRanges()))
			}
			if !IsCloudflareIP(netip.MustParseAddr("173.245.48.1")) {
				t.Fatal("builtin range must still be recognized after a rejected refresh")
			}
		})
	}
}

// Une liste rejetée ne doit pas rendre CF-Connecting-IP forgeable : c'est la
// conséquence concrète qu'un élargissement produirait (FR-02).
func TestRejectedRefreshKeepsForgedHeaderRejected(t *testing.T) {
	updater, _ := newTestUpdater(t, "0.0.0.0/0\n"+validIPv4List, validIPv6List)

	if _, err := updater.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh() error = nil, want a rejection")
	}

	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	request.RemoteAddr = "45.45.45.45:1234"
	request.Header.Set(connectingIPHeader, "1.2.3.4")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (forged CF-Connecting-IP)", response.Code)
	}
}

func TestRefreshRejectsNonOKStatus(t *testing.T) {
	t.Cleanup(resetRanges)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	updater := NewUpdater(time.Hour,
		withEndpoints(server.URL+"/ips-v4", server.URL+"/ips-v6"),
		withClient(server.Client()),
	)

	_, err := updater.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unexpected status 503") {
		t.Fatalf("error = %v, want it to mention status 503", err)
	}
	if len(Ranges()) != len(BuiltinRanges()) {
		t.Fatal("builtin list must stay in force after a failed fetch")
	}
}

func TestRefreshRejectsOversizedPayload(t *testing.T) {
	oversized := strings.Repeat("198.51.100.0/24\n", (maxPayloadBytes/16)+2)
	updater, _ := newTestUpdater(t, oversized, validIPv6List)

	_, err := updater.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("error = %v, want it to mention the payload size limit", err)
	}
}

// Les sources de production sont figées en HTTPS : la liste décide qui peut
// poser CF-Connecting-IP, elle ne peut pas voyager en clair. Seule l'option
// non exportée withEndpoints (tests) lève l'exigence.
func TestRefreshRejectsPlainHTTPSource(t *testing.T) {
	t.Cleanup(resetRanges)
	updater := NewUpdater(time.Hour)
	updater.ipv4URL = "http://example.test/ips-v4"
	updater.ipv6URL = "http://example.test/ips-v6"

	_, err := updater.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "must be https") {
		t.Fatalf("error = %v, want it to require https", err)
	}
	if updater.allowInsecureSources {
		t.Fatal("a production updater must not allow insecure sources")
	}
}

func TestDefaultEndpointsAreTheOfficialHTTPSLists(t *testing.T) {
	updater := NewUpdater(time.Hour)

	if updater.ipv4URL != "https://www.cloudflare.com/ips-v4" {
		t.Fatalf("ipv4URL = %q", updater.ipv4URL)
	}
	if updater.ipv6URL != "https://www.cloudflare.com/ips-v6" {
		t.Fatalf("ipv6URL = %q", updater.ipv6URL)
	}
}

func TestPreviouslyAdoptedListSurvivesALaterFailure(t *testing.T) {
	t.Cleanup(resetRanges)
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if strings.HasSuffix(r.URL.Path, "ips-v4") {
			_, _ = w.Write([]byte(validIPv4List))
			return
		}
		_, _ = w.Write([]byte(validIPv6List))
	}))
	t.Cleanup(server.Close)

	updater := NewUpdater(time.Hour,
		withEndpoints(server.URL+"/ips-v4", server.URL+"/ips-v6"),
		withClient(server.Client()),
	)

	if _, err := updater.Refresh(context.Background()); err != nil {
		t.Fatalf("first Refresh() error = %v", err)
	}
	fail.Store(true)
	if _, err := updater.Refresh(context.Background()); err == nil {
		t.Fatal("second Refresh() error = nil, want a failure")
	}

	if got := len(Ranges()); got != 8 {
		t.Fatalf("len(Ranges()) = %d, want the 8 previously adopted prefixes", got)
	}
}

func TestStartRefreshesOnStartupThenPeriodicallyAndStopsWithContext(t *testing.T) {
	t.Cleanup(resetRanges)
	var rounds atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "ips-v4") {
			rounds.Add(1)
			_, _ = w.Write([]byte(validIPv4List))
			return
		}
		_, _ = w.Write([]byte(validIPv6List))
	}))
	t.Cleanup(server.Close)

	var succeeded atomic.Int64
	updater := NewUpdater(20*time.Millisecond,
		withEndpoints(server.URL+"/ips-v4", server.URL+"/ips-v6"),
		withClient(server.Client()),
		WithObservers(
			func(int) { succeeded.Add(1) },
			func(err error) { t.Errorf("unexpected refresh error: %v", err) },
		),
	)

	ctx, cancel := context.WithCancel(context.Background())
	updater.Start(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for succeeded.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if succeeded.Load() < 3 {
		t.Fatalf("refreshes = %d, want at least 3 (startup + ticks)", succeeded.Load())
	}

	cancel()
	settled := rounds.Load()
	time.Sleep(100 * time.Millisecond) // plusieurs intervalles après annulation
	if after := rounds.Load(); after > settled+1 {
		t.Fatalf("rounds after cancel = %d, want it to stop near %d", after, settled)
	}
}

func TestRefreshReportsFailureToObservers(t *testing.T) {
	updater, _ := newTestUpdater(t, "nope", validIPv6List)
	var failures atomic.Int64
	WithObservers(
		func(int) { t.Error("unexpected success") },
		func(error) { failures.Add(1) },
	)(updater)

	updater.refresh(context.Background())

	if got := failures.Load(); got != 1 {
		t.Fatalf("onError calls = %d, want 1", got)
	}
}

func TestValidateFetchedRangesBounds(t *testing.T) {
	ipv4 := mustPrefixes(t, "198.51.100.0/24", "203.0.113.0/24", "192.0.2.0/24", "100.64.0.0/10")
	ipv6 := mustPrefixes(t, "2001:db8::/32", "2001:db8:1::/48", "2001:db8:2::/48", "2001:db8:3::/48")

	if err := validateFetchedRanges(ipv4, ipv6); err != nil {
		t.Fatalf("validateFetchedRanges() error = %v, want nil", err)
	}
	if err := validateFetchedRanges(ipv4[:3], ipv6); err == nil {
		t.Fatal("an ipv4 list below the floor must be rejected")
	}
	if err := validateFetchedRanges(ipv4, ipv6[:3]); err == nil {
		t.Fatal("an ipv6 list below the floor must be rejected")
	}

	oversized := make([]netip.Prefix, 0, maxPrefixesTotal+1)
	for i := range maxPrefixesTotal + 1 {
		oversized = append(oversized, netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)))
	}
	if err := validateFetchedRanges(oversized, ipv6); err == nil {
		t.Fatal("a list beyond the total cap must be rejected")
	}
}

func TestRangesFallsBackToTheBuiltinList(t *testing.T) {
	t.Cleanup(resetRanges)

	setRanges(mustPrefixes(t, "198.51.100.0/24"))
	if len(Ranges()) != 1 {
		t.Fatalf("len(Ranges()) = %d, want 1", len(Ranges()))
	}

	resetRanges()
	if len(Ranges()) != len(BuiltinRanges()) {
		t.Fatalf("len(Ranges()) = %d, want the builtin list (%d)", len(Ranges()), len(BuiltinRanges()))
	}
}

// setRanges copie la liste : une modification du slice de l'appelant après coup
// ne doit pas muter la liste que lit le chemin de requête.
func TestSetRangesCopiesTheList(t *testing.T) {
	t.Cleanup(resetRanges)

	prefixes := mustPrefixes(t, "198.51.100.0/24", "203.0.113.0/24")
	setRanges(prefixes)
	prefixes[0] = netip.MustParsePrefix("10.0.0.0/8")

	if !IsCloudflareIP(netip.MustParseAddr("198.51.100.7")) {
		t.Fatal("the active list must not follow the caller's slice")
	}
	if IsCloudflareIP(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("the active list must not follow the caller's slice")
	}
}

func mustPrefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}
