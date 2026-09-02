package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/storage"
	goredis "github.com/redis/go-redis/v9"
)

// fakeRedis rejoue les commandes réellement utilisées par le Store, sans Redis
// (ADR-002 : pas de Redis en CI). Il permet d'observer ce que le Store écrit —
// clé, TTL, charge utile — et de provoquer des pannes à la demande.
type fakeRedis struct {
	mu      sync.Mutex
	values  map[string]string
	ttls    map[string]time.Duration
	calls   map[string]int
	failing bool
	pingErr error
	closed  bool
}

func newFakeRedis() *fakeRedis {
	return &fakeRedis{
		values: make(map[string]string),
		ttls:   make(map[string]time.Duration),
		calls:  make(map[string]int),
	}
}

var errFakeDown = errors.New("connection refused")

func (f *fakeRedis) record(name string) bool {
	f.calls[name]++
	return f.failing
}

func (f *fakeRedis) Get(_ context.Context, key string) *goredis.StringCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.record("get") {
		return goredis.NewStringResult("", errFakeDown)
	}
	value, ok := f.values[key]
	if !ok {
		return goredis.NewStringResult("", goredis.Nil)
	}
	return goredis.NewStringResult(value, nil)
}

func (f *fakeRedis) MGet(_ context.Context, keys ...string) *goredis.SliceCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.record("mget") {
		return goredis.NewSliceResult(nil, errFakeDown)
	}
	values := make([]any, 0, len(keys))
	for _, key := range keys {
		if value, ok := f.values[key]; ok {
			values = append(values, value)
			continue
		}
		values = append(values, nil)
	}
	return goredis.NewSliceResult(values, nil)
}

func (f *fakeRedis) Set(_ context.Context, key string, value any, expiration time.Duration) *goredis.StatusCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.record("set") {
		return goredis.NewStatusResult("", errFakeDown)
	}
	payload, ok := value.([]byte)
	if !ok {
		return goredis.NewStatusResult("", fmt.Errorf("unexpected value type %T", value))
	}
	f.values[key] = string(payload)
	f.ttls[key] = expiration
	return goredis.NewStatusResult("OK", nil)
}

func (f *fakeRedis) Del(_ context.Context, keys ...string) *goredis.IntCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.record("del") {
		return goredis.NewIntResult(0, errFakeDown)
	}
	deleted := int64(0)
	for _, key := range keys {
		if _, ok := f.values[key]; ok {
			delete(f.values, key)
			delete(f.ttls, key)
			deleted++
		}
	}
	return goredis.NewIntResult(deleted, nil)
}

func (f *fakeRedis) Scan(_ context.Context, _ uint64, match string, _ int64) *goredis.ScanCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.record("scan") {
		return goredis.NewScanCmdResult(nil, 0, errFakeDown)
	}
	prefix := strings.TrimSuffix(match, "*")
	keys := make([]string, 0, len(f.values))
	for key := range f.values {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return goredis.NewScanCmdResult(keys, 0, nil)
}

func (f *fakeRedis) Ping(_ context.Context) *goredis.StatusCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls["ping"]++
	if f.pingErr != nil {
		return goredis.NewStatusResult("", f.pingErr)
	}
	return goredis.NewStatusResult("PONG", nil)
}

func (f *fakeRedis) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeRedis) setFailing(failing bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failing = failing
}

func (f *fakeRedis) callCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

func (f *fakeRedis) rawValue(key string) (string, time.Duration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, ok := f.values[key]
	return value, f.ttls[key], ok
}

func (f *fakeRedis) put(key string, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values[key] = value
}

// recordingObserver compte ce que le Store publie (métriques).
type recordingObserver struct {
	mu          sync.Mutex
	transitions []bool
	errors      map[string]int
}

func newRecordingObserver() *recordingObserver {
	return &recordingObserver{errors: make(map[string]int)}
}

func (o *recordingObserver) SetStorageDegraded(degraded bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.transitions = append(o.transitions, degraded)
}

func (o *recordingObserver) IncStorageError(operation string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.errors[operation]++
}

func (o *recordingObserver) transitionCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.transitions)
}

func (o *recordingObserver) lastTransition() (bool, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.transitions) == 0 {
		return false, false
	}
	return o.transitions[len(o.transitions)-1], true
}

func (o *recordingObserver) errorCount(operation string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.errors[operation]
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestStore(t *testing.T, maxVisitors int) (*Store, *fakeRedis, *recordingObserver, *testClock) {
	t.Helper()

	fake := newFakeRedis()
	observer := newRecordingObserver()
	clock := &testClock{now: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)}
	store, err := New(config.RedisConfig{Address: "fake:6379"}, maxVisitors,
		withCommander(fake),
		WithObserver(observer),
		WithClock(clock.Now),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(store.Close)
	return store, fake, observer, clock
}

func visitorFixture(expiresAt time.Time) storage.VisitorState {
	fpHash := "fp-1234"
	sticky := expiresAt.Add(-time.Minute)
	return storage.VisitorState{
		IPHash:           "d0d0cafe",
		Domain:           "example.test",
		Score:            42,
		FirstSeen:        expiresAt.Add(-time.Hour),
		LastSeen:         expiresAt.Add(-time.Minute),
		ExpiresAt:        expiresAt,
		ReqCount:         17,
		ViolationCount:   2,
		ChallengePassed:  true,
		FPHash:           &fpHash,
		StickyTrustUntil: &sticky,
		CircuitOpen:      false,
	}
}

// Redis injoignable au démarrage doit être une erreur de démarrage : démarrer en
// mémoire alors que la configuration promet un état partagé est exactement le
// défaut que ce backend corrige.
func TestNewFailsWhenRedisIsUnreachable(t *testing.T) {
	fake := newFakeRedis()
	fake.pingErr = errFakeDown

	store, err := New(config.RedisConfig{Address: "fake:6379"}, 100, withCommander(fake))
	if err == nil {
		store.Close()
		t.Fatal("New() error = nil, want a startup failure")
	}
	if !strings.Contains(err.Error(), "fake:6379") {
		t.Fatalf("error = %v, want it to name the configured address", err)
	}
	if !fake.closed {
		t.Fatal("the client must be closed when startup fails")
	}
}

func TestNewValidatesTimeout(t *testing.T) {
	cases := []struct {
		name    string
		timeout string
		want    time.Duration
		wantErr bool
	}{
		{name: "défaut", timeout: "", want: defaultTimeout},
		{name: "surcharge", timeout: "250ms", want: 250 * time.Millisecond},
		{name: "illisible", timeout: "soon", wantErr: true},
		{name: "nul", timeout: "0s", wantErr: true},
		{name: "négatif", timeout: "-1s", wantErr: true},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			store, err := New(config.RedisConfig{Address: "fake:6379", Timeout: testCase.timeout}, 100, withCommander(newFakeRedis()))
			if testCase.wantErr {
				if err == nil {
					store.Close()
					t.Fatal("New() error = nil, want a validation failure")
				}
				return
			}
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			t.Cleanup(store.Close)
			if store.timeout != testCase.want {
				t.Fatalf("timeout = %s, want %s", store.timeout, testCase.want)
			}
		})
	}
}

func TestVisitorRoundTripsThroughRedis(t *testing.T) {
	store, fake, _, clock := newTestStore(t, 100)
	expiresAt := clock.Now().Add(30 * time.Minute)
	want := visitorFixture(expiresAt)

	store.SetVisitor("d0d0cafe", want)

	raw, ttl, ok := fake.rawValue(visitorKeyPrefix + "d0d0cafe")
	if !ok {
		t.Fatalf("key %q must be written", visitorKeyPrefix+"d0d0cafe")
	}
	// Le TTL Redis dérive de l'échéance portée par l'état (ADR-021).
	if ttl != 30*time.Minute {
		t.Fatalf("ttl = %s, want 30m", ttl)
	}
	var decoded storage.VisitorState
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("stored payload is not valid JSON: %v", err)
	}

	got, found := store.GetVisitor("d0d0cafe")
	if !found {
		t.Fatal("GetVisitor() found = false, want true")
	}
	if got.Score != want.Score || got.ReqCount != want.ReqCount || got.ViolationCount != want.ViolationCount {
		t.Fatalf("visitor = %+v, want scores/counters preserved", got)
	}
	if got.FPHash == nil || *got.FPHash != "fp-1234" {
		t.Fatalf("FPHash = %v, want the pointer field to round-trip", got.FPHash)
	}
	if got.StickyTrustUntil == nil || !got.StickyTrustUntil.Equal(*want.StickyTrustUntil) {
		t.Fatalf("StickyTrustUntil = %v, want %v", got.StickyTrustUntil, want.StickyTrustUntil)
	}
	if !got.ChallengePassed {
		t.Fatal("ChallengePassed must round-trip")
	}
}

func TestBucketRoundTripsUnderItsOwnPrefix(t *testing.T) {
	store, fake, _, clock := newTestStore(t, 100)
	bucket := storage.RateBucket{
		IPHash:     "d0d0cafe",
		Tokens:     42.5,
		LastRefill: clock.Now(),
		Rate:       50,
		Capacity:   100,
		ExpiresAt:  clock.Now().Add(time.Hour),
	}

	store.SetBucket("d0d0cafe:m", bucket)

	if _, ttl, ok := fake.rawValue(bucketKeyPrefix + "d0d0cafe:m"); !ok || ttl != time.Hour {
		t.Fatalf("bucket key must be written under %q with a 1h ttl (ok=%v ttl=%s)", bucketKeyPrefix, ok, ttl)
	}
	if _, _, ok := fake.rawValue(visitorKeyPrefix + "d0d0cafe:m"); ok {
		t.Fatal("buckets and visitors must not share a key space")
	}

	got, found := store.GetBucket("d0d0cafe:m")
	if !found {
		t.Fatal("GetBucket() found = false, want true")
	}
	if got.Tokens != 42.5 || got.Rate != 50 || got.Capacity != 100 {
		t.Fatalf("bucket = %+v, want the token state preserved", got)
	}
}

// Une clé absente est une réponse valide, pas une panne : elle ne doit pas
// rapprocher le nœud du mode dégradé.
func TestMissIsNotAFailure(t *testing.T) {
	store, _, observer, _ := newTestStore(t, 100)

	for range degradedThreshold * 3 {
		if _, found := store.GetVisitor("unknown"); found {
			t.Fatal("GetVisitor() found = true, want a miss")
		}
	}

	if store.degraded() {
		t.Fatal("misses must not trigger the degraded mode")
	}
	if count := observer.transitionCount(); count != 0 {
		t.Fatalf("observer transitions = %d, want 0", count)
	}
}

// L'écart d'horloge entre le WAF et Redis peut laisser remonter une entrée d'un
// cheveu périmée : la décision suit l'horloge du WAF.
func TestExpiredEntryIsTreatedAsAbsent(t *testing.T) {
	store, fake, _, clock := newTestStore(t, 100)
	stale := visitorFixture(clock.Now().Add(-time.Second))
	payload, err := json.Marshal(stale)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	fake.put(visitorKeyPrefix+"d0d0cafe", string(payload))

	if _, found := store.GetVisitor("d0d0cafe"); found {
		t.Fatal("an entry past its deadline must read as absent")
	}
}

func TestSetVisitorWithPastDeadlineDeletesTheKey(t *testing.T) {
	store, fake, _, clock := newTestStore(t, 100)
	store.SetVisitor("d0d0cafe", visitorFixture(clock.Now().Add(time.Minute)))
	if _, _, ok := fake.rawValue(visitorKeyPrefix + "d0d0cafe"); !ok {
		t.Fatal("key must exist before the expired write")
	}

	store.SetVisitor("d0d0cafe", visitorFixture(clock.Now().Add(-time.Minute)))

	if _, _, ok := fake.rawValue(visitorKeyPrefix + "d0d0cafe"); ok {
		t.Fatal("writing an already-expired state must delete the key, not persist it")
	}
	if fake.callCount("del") == 0 {
		t.Fatal("DEL must be issued")
	}
}

func TestDeleteVisitorRemovesBothStores(t *testing.T) {
	store, fake, _, clock := newTestStore(t, 100)
	store.SetVisitor("d0d0cafe", visitorFixture(clock.Now().Add(time.Hour)))

	store.DeleteVisitor("d0d0cafe")

	if _, _, ok := fake.rawValue(visitorKeyPrefix + "d0d0cafe"); ok {
		t.Fatal("the Redis key must be deleted")
	}
	if _, found := store.local.GetVisitor("d0d0cafe"); found {
		t.Fatal("the local state must be deleted too")
	}
}

// FR-20 : sur perte de Redis, le nœud continue de fonctionner avec son état
// local. L'écriture traversante lui donne un état récent (ADR-021).
func TestDegradedModeServesTheLocalStateAfterConsecutiveFailures(t *testing.T) {
	store, fake, observer, clock := newTestStore(t, 100)
	store.SetVisitor("d0d0cafe", visitorFixture(clock.Now().Add(time.Hour)))
	fake.setFailing(true)

	for i := range degradedThreshold {
		if _, found := store.GetVisitor("d0d0cafe"); !found {
			t.Fatalf("failure %d: the local fallback must still answer", i)
		}
	}

	if !store.degraded() {
		t.Fatalf("the node must be degraded after %d consecutive failures", degradedThreshold)
	}
	if degraded, ok := observer.lastTransition(); !ok || !degraded {
		t.Fatal("the observer must be told the node is degraded")
	}
	if observer.errorCount("get_visitor") != degradedThreshold {
		t.Fatalf("get_visitor errors = %d, want %d", observer.errorCount("get_visitor"), degradedThreshold)
	}

	// En dégradé, plus aucune commande n'est émise vers Redis : le chemin de
	// requête ne paie plus de timeout.
	before := fake.callCount("get")
	visitor, found := store.GetVisitor("d0d0cafe")
	if !found || visitor.Score != 42 {
		t.Fatalf("degraded read = (%+v, %v), want the local state", visitor, found)
	}
	if after := fake.callCount("get"); after != before {
		t.Fatalf("GET calls = %d, want no Redis traffic while degraded (%d)", after, before)
	}
}

// Les écritures continuent d'alimenter l'état local en dégradé : le nœud reste
// opérationnel, seule la propagation au cluster s'interrompt.
func TestDegradedWritesStayLocal(t *testing.T) {
	store, fake, _, clock := newTestStore(t, 100)
	fake.setFailing(true)
	for range degradedThreshold {
		store.GetVisitor("warmup")
	}
	if !store.degraded() {
		t.Fatal("precondition: the node must be degraded")
	}
	fake.setFailing(false)
	setsBefore := fake.callCount("set")

	store.SetVisitor("d0d0cafe", visitorFixture(clock.Now().Add(time.Hour)))

	if fake.callCount("set") != setsBefore {
		t.Fatal("no write must reach Redis while degraded")
	}
	if _, found := store.local.GetVisitor("d0d0cafe"); !found {
		t.Fatal("the write must still land in the local store")
	}
}

func TestDegradedModeRecoversWhenRedisComesBack(t *testing.T) {
	store, fake, observer, clock := newTestStore(t, 100)
	fake.setFailing(true)
	for range degradedThreshold {
		store.GetVisitor("d0d0cafe")
	}
	if !store.degraded() {
		t.Fatal("precondition: the node must be degraded")
	}

	fake.setFailing(false)
	clock.advance(degradedWindow)
	store.SetVisitor("d0d0cafe", visitorFixture(clock.Now().Add(time.Hour)))

	if store.degraded() {
		t.Fatal("the node must be back to nominal after a successful probe")
	}
	if _, _, ok := fake.rawValue(visitorKeyPrefix + "d0d0cafe"); !ok {
		t.Fatal("writes must reach Redis again")
	}
	if degraded, ok := observer.lastTransition(); !ok || degraded {
		t.Fatal("the observer must be told the node is nominal again")
	}
}

// Après la fenêtre, une seule erreur suffit à re-basculer : sinon chaque
// fenêtre coûterait degradedThreshold timeouts sur le chemin de requête.
func TestSingleFailureWhileProbingReDegradesImmediately(t *testing.T) {
	store, fake, _, clock := newTestStore(t, 100)
	fake.setFailing(true)
	for range degradedThreshold {
		store.GetVisitor("d0d0cafe")
	}
	clock.advance(degradedWindow)
	if store.degraded() {
		t.Fatal("precondition: the window must be over")
	}

	store.GetVisitor("d0d0cafe") // sonde : elle échoue

	if !store.degraded() {
		t.Fatal("a single failure while probing must re-enter the degraded mode")
	}
}

// La jauge n'est publiée que sur transition : elle est consultée à chaque
// requête, la republier à chaque fois n'apprendrait rien.
func TestObserverIsNotifiedOnlyOnTransitions(t *testing.T) {
	store, fake, observer, _ := newTestStore(t, 100)
	fake.setFailing(true)
	for range degradedThreshold * 3 {
		store.GetVisitor("d0d0cafe")
	}

	if count := observer.transitionCount(); count != 1 {
		t.Fatalf("observer transitions = %d, want 1", count)
	}
}

func TestListVisitorsScansAndRespectsTheCap(t *testing.T) {
	store, fake, _, clock := newTestStore(t, 10)
	for i := range 50 {
		key := fmt.Sprintf("visitor-%02d", i)
		payload, err := json.Marshal(visitorFixture(clock.Now().Add(time.Hour)))
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		fake.put(visitorKeyPrefix+key, string(payload))
	}

	visitors := store.ListVisitors()

	if len(visitors) != 10 {
		t.Fatalf("visitors = %d, want the trust.max_visitors cap (10)", len(visitors))
	}
	if fake.callCount("scan") == 0 || fake.callCount("mget") == 0 {
		t.Fatalf("listing must go through SCAN + MGET (scan=%d mget=%d)", fake.callCount("scan"), fake.callCount("mget"))
	}
}

func TestListVisitorsSkipsExpiredAndUndecodableEntries(t *testing.T) {
	store, fake, observer, clock := newTestStore(t, 100)
	live, err := json.Marshal(visitorFixture(clock.Now().Add(time.Hour)))
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	stale, err := json.Marshal(visitorFixture(clock.Now().Add(-time.Hour)))
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	fake.put(visitorKeyPrefix+"live", string(live))
	fake.put(visitorKeyPrefix+"stale", string(stale))
	fake.put(visitorKeyPrefix+"broken", "{not json")

	visitors := store.ListVisitors()

	if len(visitors) != 1 {
		t.Fatalf("visitors = %d, want only the live one", len(visitors))
	}
	if observer.errorCount("decode_visitor") != 1 {
		t.Fatalf("decode errors = %d, want 1", observer.errorCount("decode_visitor"))
	}
}

func TestListVisitorsFallsBackToLocalOnScanFailure(t *testing.T) {
	store, fake, observer, clock := newTestStore(t, 100)
	store.SetVisitor("d0d0cafe", visitorFixture(clock.Now().Add(time.Hour)))
	fake.setFailing(true)

	visitors := store.ListVisitors()

	if len(visitors) != 1 {
		t.Fatalf("visitors = %d, want the local state (1)", len(visitors))
	}
	if observer.errorCount("list_visitors") != 1 {
		t.Fatalf("list_visitors errors = %d, want 1", observer.errorCount("list_visitors"))
	}
}

// Une valeur illisible n'est pas une panne de connectivité : elle ne doit pas
// faire basculer le nœud en dégradé.
func TestUndecodableValueDoesNotDegradeTheNode(t *testing.T) {
	store, fake, observer, _ := newTestStore(t, 100)
	fake.put(visitorKeyPrefix+"d0d0cafe", "{not json")
	fake.put(bucketKeyPrefix+"d0d0cafe", "{not json")

	for range degradedThreshold * 2 {
		if _, found := store.GetVisitor("d0d0cafe"); found {
			t.Fatal("an undecodable value must read as absent")
		}
		if _, found := store.GetBucket("d0d0cafe"); found {
			t.Fatal("an undecodable bucket must read as absent")
		}
	}

	if store.degraded() {
		t.Fatal("a decoding error must not trigger the degraded mode")
	}
	if observer.errorCount("decode_visitor") == 0 || observer.errorCount("decode_bucket") == 0 {
		t.Fatal("decoding errors must still be counted")
	}
}

func TestCloseClosesTheClient(t *testing.T) {
	fake := newFakeRedis()
	store, err := New(config.RedisConfig{Address: "fake:6379"}, 100, withCommander(fake))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	store.Close()

	if !fake.closed {
		t.Fatal("Close() must close the Redis client")
	}
}

// Le Store doit rester substituable au store mémoire : c'est toute la promesse
// de storage.backend.
func TestStoreSatisfiesTheStorageInterface(t *testing.T) {
	store, _, _, _ := newTestStore(t, 10)

	var _ storage.Store = store
}
