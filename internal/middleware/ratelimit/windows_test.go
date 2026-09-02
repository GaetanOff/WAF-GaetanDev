package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/storage"
	"github.com/gaetandev/waf/internal/storage/memory"
	"github.com/gaetandev/waf/internal/trust"
)

// FR-03 : la fenêtre minute borne le débit soutenu, y compris quand la fenêtre
// seconde et le burst laissent largement passer.
func TestMinuteWindowDeniesSustainedRateBelowSecondLimit(t *testing.T) {
	store := memory.New(100)
	t.Cleanup(store.Close)

	cfg := testConfig(100, 100)
	cfg.RateLimit.RequestsPerMinute = 5
	cfg.RateLimit.RequestsPerHour = 0
	cfg.Trust.BlockThreshold = -1
	middleware := newTestMiddlewareFromConfig(t, store, cfg)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	middleware.now = func() time.Time { return now }

	handler := middleware.Handler(countingHandler())
	for i := range 5 {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, requestFrom("1.2.3.4:1234"))
		if response.Code != http.StatusNoContent {
			t.Fatalf("request %d: status = %d, want 204", i, response.Code)
		}
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestFrom("1.2.3.4:1234"))
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("6th request: status = %d, want 429", response.Code)
	}
	if got := response.Header().Get("X-WAF-Reason"); got != reasonRateLimitExceededMinute {
		t.Fatalf("X-WAF-Reason = %q, want %q", got, reasonRateLimitExceededMinute)
	}
}

// FR-03 : la fenêtre heure attrape le martèlement lent — un débit sous la limite
// par minute, entretenu pendant des heures.
func TestHourWindowDeniesSlowHammering(t *testing.T) {
	store := memory.New(100)
	t.Cleanup(store.Close)

	cfg := testConfig(100, 100)
	cfg.RateLimit.RequestsPerMinute = 0
	cfg.RateLimit.RequestsPerHour = 3
	cfg.Trust.BlockThreshold = -1
	middleware := newTestMiddlewareFromConfig(t, store, cfg)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	middleware.now = func() time.Time { return now }

	handler := middleware.Handler(countingHandler())
	for i := range 3 {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, requestFrom("1.2.3.4:1234"))
		if response.Code != http.StatusNoContent {
			t.Fatalf("request %d: status = %d, want 204", i, response.Code)
		}
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestFrom("1.2.3.4:1234"))
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("4th request: status = %d, want 429", response.Code)
	}
	if got := response.Header().Get("X-WAF-Reason"); got != reasonRateLimitExceededHour {
		t.Fatalf("X-WAF-Reason = %q, want %q", got, reasonRateLimitExceededHour)
	}
}

// Le refus d'une fenêtre ne doit pas prélever le jeton des autres : sans ça, un
// client buté sur sa limite minute repartirait avec un burst à la seconde vidé.
func TestDeniedWindowDoesNotSpendOtherWindowsTokens(t *testing.T) {
	store := memory.New(100)
	t.Cleanup(store.Close)

	cfg := testConfig(10, 10)
	cfg.RateLimit.RequestsPerMinute = 1
	cfg.RateLimit.RequestsPerHour = 0
	cfg.Trust.BlockThreshold = -1
	middleware := newTestMiddlewareFromConfig(t, store, cfg)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	middleware.now = func() time.Time { return now }

	handler := middleware.Handler(countingHandler())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestFrom("1.2.3.4:1234"))
	if response.Code != http.StatusNoContent {
		t.Fatalf("first request: status = %d, want 204", response.Code)
	}

	// 5 requêtes refusées par la fenêtre minute (capacité 1, déjà consommée).
	for i := range 5 {
		refused := httptest.NewRecorder()
		handler.ServeHTTP(refused, requestFrom("1.2.3.4:1234"))
		if refused.Code != http.StatusTooManyRequests {
			t.Fatalf("refused request %d: status = %d, want 429", i, refused.Code)
		}
	}

	secondWindow, ok := store.GetBucket(trust.HashIP("1.2.3.4"))
	if !ok {
		t.Fatal("second-window bucket must be persisted under the bare ip hash")
	}
	// 10 jetons de burst, 1 seul consommé par la requête admise.
	if secondWindow.Tokens < 8.9 || secondWindow.Tokens > 9.1 {
		t.Fatalf("second-window tokens = %v, want ~9 (only the allowed request consumed one)", secondWindow.Tokens)
	}
}

// Le Retry-After annoncé est celui de la fenêtre qui rouvre le plus tard :
// annoncer le délai d'une fenêtre plus courte ferait réessayer pour rien.
func TestRetryAfterAndReasonComeFromLongestDenyingWindow(t *testing.T) {
	store := memory.New(100)
	t.Cleanup(store.Close)

	cfg := testConfig(1, 1)
	cfg.RateLimit.RequestsPerMinute = 0
	cfg.RateLimit.RequestsPerHour = 1
	cfg.Trust.BlockThreshold = -1
	middleware := newTestMiddlewareFromConfig(t, store, cfg)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	middleware.now = func() time.Time { return now }

	handler := middleware.Handler(countingHandler())
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, requestFrom("1.2.3.4:1234"))
	if first.Code != http.StatusNoContent {
		t.Fatalf("first request: status = %d, want 204", first.Code)
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestFrom("1.2.3.4:1234"))
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", response.Code)
	}
	// Fenêtre seconde : 1 s. Fenêtre heure : 3600 s. C'est la plus longue qui parle.
	if got := response.Header().Get("Retry-After"); got != "3600" {
		t.Fatalf("Retry-After = %q, want 3600", got)
	}
	if got := response.Header().Get("X-WAF-Reason"); got != reasonRateLimitExceededHour {
		t.Fatalf("X-WAF-Reason = %q, want %q", got, reasonRateLimitExceededHour)
	}
}

// `0` désactive la fenêtre : aucun bucket n'est créé pour elle, et son plafond
// ne s'applique plus.
func TestZeroDisablesWindows(t *testing.T) {
	store := memory.New(100)
	t.Cleanup(store.Close)

	cfg := testConfig(1000, 1000)
	cfg.RateLimit.RequestsPerMinute = 0
	cfg.RateLimit.RequestsPerHour = 0
	cfg.Trust.BlockThreshold = -1
	middleware := newTestMiddlewareFromConfig(t, store, cfg)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	middleware.now = func() time.Time { return now }

	if len(middleware.windows) != 1 {
		t.Fatalf("windows = %d, want 1 (second only)", len(middleware.windows))
	}

	handler := middleware.Handler(countingHandler())
	for i := range 200 {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, requestFrom("1.2.3.4:1234"))
		if response.Code != http.StatusNoContent {
			t.Fatalf("request %d: status = %d, want 204", i, response.Code)
		}
	}

	ipHash := trust.HashIP("1.2.3.4")
	if _, ok := store.GetBucket(ipHash + minuteKeySuffix); ok {
		t.Fatal("minute bucket must not be persisted when the window is disabled")
	}
	if _, ok := store.GetBucket(ipHash + hourKeySuffix); ok {
		t.Fatal("hour bucket must not be persisted when the window is disabled")
	}
}

// FR-08 : un 429 imputable au seul resserrement de pression reste neutre, y
// compris quand c'est une fenêtre minute/heure qui refuse.
func TestPressureThrottleOnMinuteWindowStaysNeutral(t *testing.T) {
	store := memory.New(100)
	t.Cleanup(store.Close)

	cfg := testConfig(1000, 1000)
	cfg.RateLimit.RequestsPerMinute = 10
	cfg.RateLimit.RequestsPerHour = 0
	middleware := newTestMiddlewareFromConfig(t, store, cfg)
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	middleware.now = func() time.Time { return now }

	// Fenêtre minute vide, rechargée depuis 6 s. Au débit nominal (10/60 s) elle
	// a regagné 1 jeton ; au débit resserré de moitié, seulement 0,5.
	ipHash := trust.HashIP("6.6.6.6")
	store.SetBucket(ipHash+minuteKeySuffix, storage.RateBucket{
		IPHash:     ipHash,
		Tokens:     0,
		LastRefill: now.Add(-6 * time.Second),
		Rate:       10.0 / 60.0,
		Capacity:   10,
		ExpiresAt:  time.Now().Add(time.Minute),
	})

	handler := middleware.Handler(countingHandler())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, requestWithPressure("6.6.6.6:1234", pressureHigh))

	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", response.Code)
	}
	if got := response.Header().Get("X-WAF-Reason"); got != ReasonPressureThrottle {
		t.Fatalf("X-WAF-Reason = %q, want %q", got, ReasonPressureThrottle)
	}
	visitor := middleware.scores.Get("6.6.6.6", "example.test")
	if visitor.Score != cfg.Trust.InitialScore {
		t.Fatalf("score = %d, want %d (pressure throttle must not penalize)", visitor.Score, cfg.Trust.InitialScore)
	}
}

func TestBuildWindows(t *testing.T) {
	cases := []struct {
		name       string
		perMinute  int
		perHour    int
		wantCount  int
		wantSuffix []string
	}{
		{name: "les trois fenêtres", perMinute: 600, perHour: 3600, wantCount: 3, wantSuffix: []string{"", minuteKeySuffix, hourKeySuffix}},
		{name: "minute seule", perMinute: 600, perHour: 0, wantCount: 2, wantSuffix: []string{"", minuteKeySuffix}},
		{name: "heure seule", perMinute: 0, perHour: 3600, wantCount: 2, wantSuffix: []string{"", hourKeySuffix}},
		{name: "seconde seule", perMinute: 0, perHour: 0, wantCount: 1, wantSuffix: []string{""}},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			windows := buildWindows(config.RateLimit{
				RequestsPerSecond: 50,
				Burst:             100,
				RequestsPerMinute: testCase.perMinute,
				RequestsPerHour:   testCase.perHour,
			})
			if len(windows) != testCase.wantCount {
				t.Fatalf("windows = %d, want %d", len(windows), testCase.wantCount)
			}
			for i, suffix := range testCase.wantSuffix {
				if windows[i].keySuffix != suffix {
					t.Fatalf("windows[%d].keySuffix = %q, want %q", i, windows[i].keySuffix, suffix)
				}
			}
			// La fenêtre seconde garde burst comme capacité et la clé nue :
			// l'état persisté des déploiements antérieurs reste lisible.
			if windows[0].capacity != 100 || windows[0].rate != 50 || windows[0].ttl != defaultBucketTTL {
				t.Fatalf("second window = %+v, want rate 50 / capacity 100 / ttl %s", windows[0], defaultBucketTTL)
			}
		})
	}
}

// Le débit de recharge d'une fenêtre vaut la limite divisée par sa durée, et sa
// capacité vaut la limite : c'est ce qui fait que la fenêtre borne un cumul.
func TestWindowRatesMatchTheirDuration(t *testing.T) {
	windows := buildWindows(config.RateLimit{
		RequestsPerSecond: 50,
		Burst:             100,
		RequestsPerMinute: 600,
		RequestsPerHour:   3600,
	})

	minute := windows[1]
	if minute.rate != 10 || minute.capacity != 600 || minute.ttl != time.Minute {
		t.Fatalf("minute window = %+v, want rate 10 / capacity 600 / ttl 1m", minute)
	}
	hour := windows[2]
	if hour.rate != 1 || hour.capacity != 3600 || hour.ttl != time.Hour {
		t.Fatalf("hour window = %+v, want rate 1 / capacity 3600 / ttl 1h", hour)
	}
}

func TestVerdictPicksLongestDelayAndItsReason(t *testing.T) {
	cases := []struct {
		name           string
		evaluations    []evaluation
		wantAllowed    bool
		wantRetryAfter time.Duration
		wantReason     string
	}{
		{
			name: "toutes les fenêtres autorisent",
			evaluations: []evaluation{
				{window: window{reason: reasonRateLimitExceeded}, allowed: true},
				{window: window{reason: reasonRateLimitExceededHour}, allowed: true},
			},
			wantAllowed: true,
			wantReason:  reasonRateLimitExceeded,
		},
		{
			name: "la fenêtre la plus longue décide",
			evaluations: []evaluation{
				{window: window{reason: reasonRateLimitExceeded}, allowed: false, retryAfter: time.Second},
				{window: window{reason: reasonRateLimitExceededMinute}, allowed: false, retryAfter: 30 * time.Second},
				{window: window{reason: reasonRateLimitExceededHour}, allowed: false, retryAfter: time.Hour},
			},
			wantAllowed:    false,
			wantRetryAfter: time.Hour,
			wantReason:     reasonRateLimitExceededHour,
		},
		{
			name: "une seule fenêtre refuse",
			evaluations: []evaluation{
				{window: window{reason: reasonRateLimitExceeded}, allowed: true},
				{window: window{reason: reasonRateLimitExceededMinute}, allowed: false, retryAfter: 12 * time.Second},
			},
			wantAllowed:    false,
			wantRetryAfter: 12 * time.Second,
			wantReason:     reasonRateLimitExceededMinute,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			allowed, retryAfter, reason := verdict(testCase.evaluations)
			if allowed != testCase.wantAllowed {
				t.Fatalf("allowed = %v, want %v", allowed, testCase.wantAllowed)
			}
			if retryAfter != testCase.wantRetryAfter {
				t.Fatalf("retryAfter = %s, want %s", retryAfter, testCase.wantRetryAfter)
			}
			if reason != testCase.wantReason {
				t.Fatalf("reason = %q, want %q", reason, testCase.wantReason)
			}
		})
	}
}

// Refill recharge sans prélever : deux appels consécutifs ne consomment rien.
func TestRefillDoesNotConsume(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	bucket := NewTokenBucket(1, 3, now)

	for i := range 5 {
		allowed, retryAfter := bucket.Refill(now)
		if !allowed || retryAfter != 0 {
			t.Fatalf("Refill #%d = (%v, %s), want (true, 0)", i, allowed, retryAfter)
		}
	}
	if tokens := bucket.Snapshot(now, time.Minute, "hash").Tokens; tokens != 3 {
		t.Fatalf("tokens = %v, want 3 (Refill must not consume)", tokens)
	}

	if !bucket.Consume() {
		t.Fatal("Consume() = false, want true")
	}
	if tokens := bucket.Snapshot(now, time.Minute, "hash").Tokens; tokens != 2 {
		t.Fatalf("tokens = %v, want 2 after one Consume", tokens)
	}
}

func TestConsumeReportsEmptyBucket(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	bucket := NewTokenBucket(1, 1, now)

	if !bucket.Consume() {
		t.Fatal("first Consume() = false, want true")
	}
	if bucket.Consume() {
		t.Fatal("second Consume() = true, want false (bucket is empty)")
	}
	allowed, retryAfter := bucket.Refill(now)
	if allowed {
		t.Fatal("Refill() allowed = true, want false on an empty bucket")
	}
	if retryAfter != time.Second {
		t.Fatalf("retryAfter = %s, want 1s (rate 1/s)", retryAfter)
	}
}
