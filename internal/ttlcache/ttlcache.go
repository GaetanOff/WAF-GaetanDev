// Package ttlcache fournit une map bornée en taille et en âge pour l'état
// indexé par IP (ou hash d'IP) que tiennent les détecteurs. Une map nue y
// grossissait sans limite : chaque IP vue restait en mémoire, et un DDoS
// distribué sur des centaines de milliers d'IP épuisait la RAM du WAF.
//
// La borne de taille est une éviction LRU ; l'âge est vérifié à la lecture.
// Aucune goroutine : une entrée périmée jamais relue finit évincée par la
// pression de taille, qui borne à elle seule la mémoire.
package ttlcache

import (
	"container/list"
	"sync"
	"time"
)

// Cache est sûr pour un usage concurrent.
type Cache[K comparable, V any] struct {
	maxEntries int
	ttl        time.Duration
	now        func() time.Time

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
	return &Cache[K, V]{
		maxEntries: maxEntries,
		ttl:        ttl,
		now:        time.Now,
		items:      make(map[K]*list.Element),
		order:      list.New(),
	}
}

// WithClock remplace l'horloge (tests).
func (c *Cache[K, V]) WithClock(now func() time.Time) *Cache[K, V] {
	c.now = now
	return c
}

// Get retourne la valeur vivante de key.
func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.getLocked(key)
}

// Set écrit value avec le TTL par défaut.
func (c *Cache[K, V]) Set(key K, value V) {
	c.SetWithTTL(key, value, c.ttl)
}

// SetWithTTL écrit value valable ttl (ttl <= 0 : pas d'expiration).
func (c *Cache[K, V]) SetWithTTL(key K, value V, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setLocked(key, value, ttl)
}

// Update lit, transforme et réécrit key sous un seul verrou (lecture-écriture
// atomique). fn reçoit la valeur vivante et sa présence.
func (c *Cache[K, V]) Update(key K, fn func(current V, found bool) V) V {
	c.mu.Lock()
	defer c.mu.Unlock()
	current, found := c.getLocked(key)
	next := fn(current, found)
	c.setLocked(key, next, c.ttl)
	return next
}

// Delete retire key.
func (c *Cache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if element, ok := c.items[key]; ok {
		c.removeLocked(element)
	}
}

// Len retourne le nombre d'entrées, périmées non encore évincées comprises.
func (c *Cache[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

func (c *Cache[K, V]) getLocked(key K) (V, bool) {
	var zero V
	element, ok := c.items[key]
	if !ok {
		return zero, false
	}
	item := element.Value.(*entry[K, V])
	if !item.expiresAt.IsZero() && !item.expiresAt.After(c.now()) {
		c.removeLocked(element)
		return zero, false
	}
	c.order.MoveToFront(element)
	return item.value, true
}

func (c *Cache[K, V]) setLocked(key K, value V, ttl time.Duration) {
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = c.now().Add(ttl)
	}
	if element, ok := c.items[key]; ok {
		item := element.Value.(*entry[K, V])
		item.value, item.expiresAt = value, expiresAt
		c.order.MoveToFront(element)
		return
	}
	c.items[key] = c.order.PushFront(&entry[K, V]{key: key, value: value, expiresAt: expiresAt})
	for len(c.items) > c.maxEntries {
		c.removeLocked(c.order.Back())
	}
}

func (c *Cache[K, V]) removeLocked(element *list.Element) {
	item := element.Value.(*entry[K, V])
	delete(c.items, item.key)
	c.order.Remove(element)
}
