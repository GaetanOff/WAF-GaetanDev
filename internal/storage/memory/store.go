package memory

import (
	"container/list"
	"hash/maphash"
	"slices"
	"sync"
	"time"

	"github.com/gaetandev/waf/internal/storage"
)

const cleanupInterval = 60 * time.Second

// bucketsPerVisitor est le nombre de buckets de rate limiting qu'une même IP
// peut occuper : une par fenêtre seconde / minute / heure (FR-03). La borne du
// nombre de buckets en est le multiple — sans ce facteur, activer les fenêtres
// diviserait par trois le nombre d'IP réellement suivies pour un même
// trust.max_visitors.
const bucketsPerVisitor = 3

// bucketLockStripes répartit les verrous de UpdateBuckets : les mises à jour
// d'IP différentes ne se sérialisent pas entre elles.
const bucketLockStripes = 64

type Store struct {
	maxVisitors int
	now         func() time.Time

	mu       sync.Mutex
	visitors sync.Map
	buckets  sync.Map
	lru      *list.List
	lruIndex map[string]*list.Element
	count    int

	bucketSeed  maphash.Seed
	bucketLocks [bucketLockStripes]sync.Mutex

	done      chan struct{}
	closeOnce sync.Once
}

// Option configure un Store à la construction.
type Option func(*Store)

// WithClock injecte l'horloge du Store. Sert à partager UNE horloge entre le
// Store et le ScoreManager (tests déterministes) : l'éviction (ExpiresAt) et le
// scoring lisent alors le même temps. Sans ça, un Store sur time.Now peut évincer
// un visiteur que le manager, tournant sur une horloge injectée, croit encore
// vivant. Un now nil est ignoré (l'horloge par défaut time.Now est conservée).
func WithClock(now func() time.Time) Option {
	return func(s *Store) {
		if now != nil {
			s.now = now
		}
	}
}

func New(maxVisitors int, opts ...Option) *Store {
	if maxVisitors < 1 {
		maxVisitors = 1
	}

	store := &Store{
		maxVisitors: maxVisitors,
		now:         time.Now,
		lru:         list.New(),
		lruIndex:    make(map[string]*list.Element),
		bucketSeed:  maphash.MakeSeed(),
		done:        make(chan struct{}),
	}
	for _, opt := range opts {
		opt(store)
	}
	go store.cleanupLoop()

	return store
}

func (s *Store) GetVisitor(key string) (*storage.VisitorState, bool) {
	value, ok := s.visitors.Load(key)
	if !ok {
		return nil, false
	}
	visitor, ok := value.(storage.VisitorState)
	if !ok {
		s.visitors.Delete(key)
		return nil, false
	}
	if isExpired(s.now(), visitor.ExpiresAt) {
		s.DeleteVisitor(key)
		return nil, false
	}

	// Lecture sans verrou : sync.Map.Load est concurrent, et on ne fait PAS de
	// « touch » LRU ici. Chaque requête appelle GetVisitor plusieurs fois ; le
	// faire sous s.mu sérialisait le chemin chaud. L'éviction suit donc l'ordre
	// du dernier SetVisitor (les visiteurs actifs sont écrits via Apply, donc
	// récents) : approximation « least-recently-set » de la LRU.
	return cloneVisitor(visitor), true
}

func (s *Store) SetVisitor(key string, visitor storage.VisitorState) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.visitors.Load(key); !exists {
		s.count++
	}
	s.visitors.Store(key, visitor)
	s.touchLocked(key)
	s.evictVisitorsLocked()
}

func (s *Store) DeleteVisitor(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.deleteVisitorLocked(key)
}

func (s *Store) ListVisitors() []storage.VisitorState {
	now := s.now()
	visitors := make([]storage.VisitorState, 0)
	s.visitors.Range(func(key, value any) bool {
		keyString, ok := key.(string)
		if !ok {
			return true
		}
		visitor, ok := value.(storage.VisitorState)
		if !ok {
			s.visitors.Delete(keyString)
			return true
		}
		if isExpired(now, visitor.ExpiresAt) {
			s.DeleteVisitor(keyString)
			return true
		}
		visitors = append(visitors, *cloneVisitor(visitor))
		return true
	})
	return visitors
}

func (s *Store) GetBucket(key string) (*storage.RateBucket, bool) {
	value, ok := s.buckets.Load(key)
	if !ok {
		return nil, false
	}
	bucket, ok := value.(storage.RateBucket)
	if !ok {
		s.buckets.Delete(key)
		return nil, false
	}
	if isExpired(s.now(), bucket.ExpiresAt) {
		s.buckets.Delete(key)
		return nil, false
	}

	return &bucket, true
}

func (s *Store) SetBucket(key string, bucket storage.RateBucket) {
	s.buckets.Store(key, bucket)
}

// UpdateBuckets verrouille le groupe de clés le temps de lire, calculer et
// écrire. Le verrou est choisi par la première clé : les clés d'un même appel
// sont celles d'une même IP (fenêtres seconde, minute, heure), et tout appel
// portant sur cette IP prend le même verrou.
func (s *Store) UpdateBuckets(keys []string, update func(current []*storage.RateBucket) []storage.RateBucket) {
	if len(keys) == 0 {
		return
	}
	lock := &s.bucketLocks[maphash.String(s.bucketSeed, keys[0])%bucketLockStripes]
	lock.Lock()
	defer lock.Unlock()

	current := make([]*storage.RateBucket, len(keys))
	for i, key := range keys {
		current[i], _ = s.GetBucket(key)
	}
	next := update(current)
	for i := range next {
		s.SetBucket(keys[i], next[i])
	}
}

// CleanupExpired purge les entrées expirées et borne le nombre de buckets.
//
// Le balayage NE tient PAS le verrou s.mu : on collecte d'abord les clés
// expirées via Range (sûr et concurrent sur sync.Map), puis on supprime par clé
// sous verrou court. Auparavant, s.mu était tenu pendant TOUT le balayage des
// deux maps — or chaque requête prend s.mu sur chaque GetVisitor, donc le sweep
// figeait toutes les requêtes pendant sa durée (gels périodiques ~toutes les
// 60s sous charge, proportionnels à la taille des maps).
func (s *Store) CleanupExpired() {
	now := s.now()

	var expiredVisitors []string
	s.visitors.Range(func(key, value any) bool {
		keyString, ok := key.(string)
		if !ok {
			return true
		}
		visitor, ok := value.(storage.VisitorState)
		if !ok {
			s.visitors.Delete(keyString)
			return true
		}
		if isExpired(now, visitor.ExpiresAt) {
			expiredVisitors = append(expiredVisitors, keyString)
		}
		return true
	})
	for _, key := range expiredVisitors {
		s.DeleteVisitor(key) // verrou court par clé, jamais tenu pendant tout le sweep
	}

	s.cleanupBuckets(now)
}

// cleanupBuckets supprime les buckets expirés puis borne leur nombre à
// maxVisitors * bucketsPerVisitor en évinçant les moins récemment rafraîchis.
// Les buckets n'ont pas
// d'éviction LRU propre (SetBucket est lock-free) : sans cette borne, la map
// grossit indéfiniment avec le nombre d'IP vues.
// cleanupBuckets purge les buckets expirés puis, au-delà de la borne, évince
// les moins récemment rechargés. Le premier passage ne fait que compter : la
// liste des buckets vivants (jusqu'à trust.max_visitors × 3 entrées) était
// construite par ajouts successifs à chaque passe, même sous la borne, qui est
// le cas courant.
func (s *Store) cleanupBuckets(now time.Time) {
	live := 0
	s.buckets.Range(func(key, value any) bool {
		bucket, ok := value.(storage.RateBucket)
		if !ok || isExpired(now, bucket.ExpiresAt) {
			s.buckets.Delete(key)
			return true
		}
		live++
		return true
	})
	maxBuckets := s.maxVisitors * bucketsPerVisitor
	if live <= maxBuckets {
		return
	}
	s.evictOldestBuckets(live, maxBuckets)
}

// evictOldestBuckets retire les buckets les moins récemment rechargés jusqu'à
// revenir à maxBuckets. live dimensionne la collecte en une allocation.
func (s *Store) evictOldestBuckets(live int, maxBuckets int) {
	type agedBucket struct {
		key  any
		last time.Time
	}
	aged := make([]agedBucket, 0, live)
	s.buckets.Range(func(key, value any) bool {
		if bucket, ok := value.(storage.RateBucket); ok {
			aged = append(aged, agedBucket{key: key, last: bucket.LastRefill})
		}
		return true
	})
	if len(aged) <= maxBuckets {
		return
	}
	slices.SortFunc(aged, func(a, b agedBucket) int { return a.last.Compare(b.last) })
	for _, b := range aged[:len(aged)-maxBuckets] {
		s.buckets.Delete(b.key)
	}
}

// Close arrête la boucle de nettoyage. Idempotent, y compris en appels
// concurrents : le select/default précédent laissait deux appelants simultanés
// passer tous deux par default, et le second close paniquait.
func (s *Store) Close() {
	s.closeOnce.Do(func() { close(s.done) })
}

func (s *Store) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.CleanupExpired()
		case <-s.done:
			return
		}
	}
}

func (s *Store) touchLocked(key string) {
	if element, ok := s.lruIndex[key]; ok {
		s.lru.MoveToFront(element)
		return
	}
	s.lruIndex[key] = s.lru.PushFront(key)
}

func (s *Store) evictVisitorsLocked() {
	for s.count > s.maxVisitors {
		element := s.lru.Back()
		if element == nil {
			return
		}
		key, _ := element.Value.(string)
		s.deleteVisitorLocked(key)
	}
}

func (s *Store) deleteVisitorLocked(key string) {
	if _, exists := s.visitors.Load(key); exists {
		s.count--
	}
	s.visitors.Delete(key)
	if element, ok := s.lruIndex[key]; ok {
		s.lru.Remove(element)
		delete(s.lruIndex, key)
	}
}

func isExpired(now time.Time, expiresAt time.Time) bool {
	return !expiresAt.IsZero() && !expiresAt.After(now)
}

func cloneVisitor(visitor storage.VisitorState) *storage.VisitorState {
	if visitor.FPHash != nil {
		fpHash := *visitor.FPHash
		visitor.FPHash = &fpHash
	}
	if visitor.StickyTrustUntil != nil {
		stickyTrustUntil := *visitor.StickyTrustUntil
		visitor.StickyTrustUntil = &stickyTrustUntil
	}
	if visitor.CircuitOpenUntil != nil {
		circuitOpenUntil := *visitor.CircuitOpenUntil
		visitor.CircuitOpenUntil = &circuitOpenUntil
	}
	if visitor.LastViolation != nil {
		lastViolation := *visitor.LastViolation
		visitor.LastViolation = &lastViolation
	}
	return &visitor
}
