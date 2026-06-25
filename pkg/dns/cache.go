package dns

import (
	"container/list"
	"sync"
	"time"
)

// CacheEntry stores a DNS response with TTL tracking.
type CacheEntry struct {
	Question string
	Answer   []byte
	ExpireAt time.Time
}

// Cache is a TTL-aware LRU DNS response cache.
type Cache struct {
	mu        sync.RWMutex
	entries   map[string]*list.Element
	lru       *list.List
	maxSize   int
	defaultTTL time.Duration
}

type cacheItem struct {
	key   string
	entry *CacheEntry
}

func NewCache(maxSize int, defaultTTL time.Duration) *Cache {
	if maxSize <= 0 {
		maxSize = 1024
	}
	if defaultTTL <= 0 {
		defaultTTL = 5 * time.Minute
	}
	return &Cache{
		entries:    make(map[string]*list.Element),
		lru:        list.New(),
		maxSize:    maxSize,
		defaultTTL: defaultTTL,
	}
}

// Get returns a cached response. Returns nil if not found or expired.
func (c *Cache) Get(question string) []byte {
	c.mu.RLock()
	elem, exists := c.entries[question]
	if !exists {
		c.mu.RUnlock()
		return nil
	}
	item := elem.Value.(*cacheItem)
	if time.Now().After(item.entry.ExpireAt) {
		c.mu.RUnlock()
		c.Delete(question)
		return nil
	}
	c.mu.RUnlock()
	c.mu.Lock()
	c.lru.MoveToFront(elem)
	c.mu.Unlock()
	return item.entry.Answer
}

// Put stores a DNS response with TTL.
func (c *Cache) Put(question string, answer []byte, ttl time.Duration) {
	if ttl <= 0 {
		ttl = c.defaultTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, exists := c.entries[question]; exists {
		c.lru.MoveToFront(elem)
		item := elem.Value.(*cacheItem)
		item.entry.Answer = answer
		item.entry.ExpireAt = time.Now().Add(ttl)
		return
	}

	if len(c.entries) >= c.maxSize {
		c.evictLocked()
	}

	elem := c.lru.PushFront(&cacheItem{
		key: question,
		entry: &CacheEntry{
			Question: question,
			Answer:   answer,
			ExpireAt: time.Now().Add(ttl),
		},
	})
	c.entries[question] = elem
}

// Delete removes a cached entry.
func (c *Cache) Delete(question string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, exists := c.entries[question]; exists {
		c.lru.Remove(elem)
		delete(c.entries, question)
	}
}

func (c *Cache) evictLocked() {
	elem := c.lru.Back()
	if elem == nil {
		return
	}
	item := elem.Value.(*cacheItem)
	c.lru.Remove(elem)
	delete(c.entries, item.key)
}

// Count returns the number of cached entries.
func (c *Cache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// GC removes expired entries.
func (c *Cache) GC() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	removed := 0
	for key, elem := range c.entries {
		item := elem.Value.(*cacheItem)
		if now.After(item.entry.ExpireAt) {
			c.lru.Remove(elem)
			delete(c.entries, key)
			removed++
		}
	}
	return removed
}

// StartGC runs periodic GC in a goroutine.
func (c *Cache) StartGC(interval time.Duration, stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.GC()
			case <-stop:
				return
			}
		}
	}()
}
