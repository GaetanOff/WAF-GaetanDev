// Package ttlcache fournit une map bornée en taille et en âge pour l'état
// indexé par IP (ou hash d'IP) que tiennent les détecteurs. Une map nue y
// grossissait sans limite : chaque IP vue restait en mémoire, et un DDoS
// distribué sur des centaines de milliers d'IP épuisait la RAM du WAF.
//
// La borne de taille est une éviction LRU ; l'âge est vérifié à la lecture.
// Aucune goroutine : une entrée périmée jamais relue finit évincée par la
// pression de taille, qui borne à elle seule la mémoire.
//
// Un grand cache est réparti en segments indépendants, chacun avec son verrou
// et son LRU : une lecture réordonne la liste LRU, donc prend un verrou
// exclusif, et un verrou unique sérialisait toutes les requêtes concurrentes
// qui lisaient le cache. L'éviction reste LRU au sein de chaque segment ; la
// borne globale est tenue, mais un segment peut évincer avant que les autres
// soient pleins (à saturation, ~99 % de la capacité est occupée).
package ttlcache

import (
	"container/list"
	"hash/maphash"
	"sync"
	"time"
)

const (
	// shardCount est le nombre de segments d'un grand cache.
	shardCount = 32
	// minEntriesPerShard : sous shardCount × minEntriesPerShard entrées, le
	// cache garde un segment unique et un LRU exact ; segmenter un petit cache
	// évincerait par segment bien avant la borne globale.
	minEntriesPerShard = 256
)

// Cache est sûr pour un usage concurrent.
type Cache[K comparable, V any] struct {
	ttl    time.Duration
	now    func() time.Time
	seed   maphash.Seed
	shards []*shard[K, V]
}

type shard[K comparable, V any] struct {
	maxEntries int

	mu    sync.Mutex
	items map[K]*list.Element
	order *list.List // front = plus récemment écrit ou lu
}

type entry[K comparable, V any] struct {
	key       K
	value     V
	expiresAt time.Time
}

// New construit un cache d'au plus maxEntries entrées (minimum 1), chacune
// valable ttl après sa dernière écriture (ttl <= 0 : pas d'expiration).
func New[K comparable, V any](maxEntries int, ttl time.Duration) *Cache[K, V] {
	if maxEntries < 1 {
		maxEntries = 1
	}
	count := 1
	if maxEntries >= shardCount*minEntriesPerShard {
		count = shardCount
	}
	shards := make([]*shard[K, V], count)
	for i := range shards {
		// Le reste de la division est réparti sur les premiers segments : la
		// somme des bornes vaut exactement maxEntries.
		capacity := maxEntries / count
		if i < maxEntries%count {
			capacity++
		}
		shards[i] = &shard[K, V]{
			maxEntries: capacity,
			items:      make(map[K]*list.Element),
			order:      list.New(),
		}
	}
	return &Cache[K, V]{
		ttl:    ttl,
		now:    time.Now,
		seed:   maphash.MakeSeed(),
		shards: shards,
	}
}

// WithClock remplace l'horloge (tests).
func (c *Cache[K, V]) WithClock(now func() time.Time) *Cache[K, V] {
	c.now = now
	return c
}

// Get retourne la valeur vivante de key.
func (c *Cache[K, V]) Get(key K) (V, bool) {
	s := c.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(key, c.now())
}

// Set écrit value avec le TTL par défaut.
func (c *Cache[K, V]) Set(key K, value V) {
	c.SetWithTTL(key, value, c.ttl)
}

// SetWithTTL écrit value valable ttl (ttl <= 0 : pas d'expiration).
func (c *Cache[K, V]) SetWithTTL(key K, value V, ttl time.Duration) {
	s := c.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setLocked(key, value, expiry(c.now(), ttl))
}

// Update lit, transforme et réécrit key sous un seul verrou (lecture-écriture
// atomique). fn reçoit la valeur vivante et sa présence.
func (c *Cache[K, V]) Update(key K, fn func(current V, found bool) V) V {
	s := c.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := c.now()
	current, found := s.getLocked(key, now)
	next := fn(current, found)
	s.setLocked(key, next, expiry(now, c.ttl))
	return next
}

// Delete retire key.
func (c *Cache[K, V]) Delete(key K) {
	s := c.shardFor(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if element, ok := s.items[key]; ok {
		s.removeLocked(element)
	}
}

// Len retourne le nombre d'entrées, périmées non encore évincées comprises.
func (c *Cache[K, V]) Len() int {
	total := 0
	for _, s := range c.shards {
		s.mu.Lock()
		total += len(s.items)
		s.mu.Unlock()
	}
	return total
}

func (c *Cache[K, V]) shardFor(key K) *shard[K, V] {
	if len(c.shards) == 1 {
		return c.shards[0]
	}
	return c.shards[maphash.Comparable(c.seed, key)%uint64(len(c.shards))]
}

func expiry(now time.Time, ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return now.Add(ttl)
}

func (s *shard[K, V]) getLocked(key K, now time.Time) (V, bool) {
	var zero V
	element, ok := s.items[key]
	if !ok {
		return zero, false
	}
	item := element.Value.(*entry[K, V])
	if !item.expiresAt.IsZero() && !item.expiresAt.After(now) {
		s.removeLocked(element)
		return zero, false
	}
	s.order.MoveToFront(element)
	return item.value, true
}

func (s *shard[K, V]) setLocked(key K, value V, expiresAt time.Time) {
	if element, ok := s.items[key]; ok {
		item := element.Value.(*entry[K, V])
		item.value, item.expiresAt = value, expiresAt
		s.order.MoveToFront(element)
		return
	}
	s.items[key] = s.order.PushFront(&entry[K, V]{key: key, value: value, expiresAt: expiresAt})
	for len(s.items) > s.maxEntries {
		s.removeLocked(s.order.Back())
	}
}

func (s *shard[K, V]) removeLocked(element *list.Element) {
	item := element.Value.(*entry[K, V])
	delete(s.items, item.key)
	s.order.Remove(element)
}
