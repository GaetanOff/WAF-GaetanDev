package memory

import (
	"container/list"
	"sync"
	"time"

	"github.com/gaetandev/waf/internal/storage"
)

const cleanupInterval = 60 * time.Second

type Store struct {
	maxVisitors int
	now         func() time.Time

	mu       sync.Mutex
	visitors sync.Map
	buckets  sync.Map
	lru      *list.List
	lruIndex map[string]*list.Element
	count    int

	done chan struct{}
}

func New(maxVisitors int) *Store {
	if maxVisitors < 1 {
		maxVisitors = 1
	}

	store := &Store{
		maxVisitors: maxVisitors,
		now:         time.Now,
		lru:         list.New(),
		lruIndex:    make(map[string]*list.Element),
		done:        make(chan struct{}),
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

	s.mu.Lock()
	s.touchLocked(key)
	s.mu.Unlock()

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

func (s *Store) CleanupExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
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
			s.deleteVisitorLocked(keyString)
		}
		return true
	})
	s.buckets.Range(func(key, value any) bool {
		keyString, ok := key.(string)
		if !ok {
			return true
		}
		bucket, ok := value.(storage.RateBucket)
		if !ok {
			s.buckets.Delete(keyString)
			return true
		}
		if isExpired(now, bucket.ExpiresAt) {
			s.buckets.Delete(keyString)
		}
		return true
	})
}

func (s *Store) Close() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
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
	return &visitor
}
