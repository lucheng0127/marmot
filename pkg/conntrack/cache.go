package conntrack

import (
	"sync"
	"time"

	"github.com/lucheng0127/marmot/pkg/tproxy"
)

// FlowKey is the 5-tuple identifying a network flow.
// Reuses tproxy.FlowKey to ensure type compatibility with TProxy.
type FlowKey = tproxy.FlowKey

// FlowEntry stores the cached decision for a single flow.
// Per Phase 2 design: DO NOT add Domain/RuleID/DNS fields here.
// This is a Flow cache, not a Rule cache.
type FlowEntry struct {
	Decision tproxy.Decision // Direct or Proxy
	LastSeen time.Time       // last access time, used for GC eviction
	HitCount uint64          // number of times this flow was looked up
}

// Cache is the Conntrack Cache — a thread-safe in-memory map
// that stores flow decisions and syncs them to the BPF Flow Map.
type Cache struct {
	mu      sync.RWMutex
	entries map[FlowKey]*FlowEntry
	ttl     time.Duration
	maxSize int

	// BPF sync callback — set by the integration layer
	BPFWriter func(key FlowKey, d tproxy.Decision) error
}

// New creates a new Conntrack Cache.
// ttl: entry time-to-live (default 1h for TCP, 2min for UDP)
// maxSize: maximum number of entries before LRU eviction
func New(ttl time.Duration, maxSize int) *Cache {
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	if maxSize <= 0 {
		maxSize = 65536
	}
	return &Cache{
		entries: make(map[FlowKey]*FlowEntry),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

// Insert adds or updates a flow entry.
// It also triggers BPF map writeback if BPFWriter is set.
func (c *Cache) Insert(key FlowKey, d tproxy.Decision) error {
	c.mu.Lock()
	now := time.Now()

	entry, exists := c.entries[key]
	if exists {
		entry.Decision = d
		entry.LastSeen = now
		entry.HitCount++
	} else {
		// Check size limit before inserting
		if len(c.entries) >= c.maxSize {
			c.evictLocked()
		}
		c.entries[key] = &FlowEntry{
			Decision: d,
			LastSeen: now,
			HitCount: 1,
		}
	}
	c.mu.Unlock()

	// Sync to BPF map (outside the lock)
	if c.BPFWriter != nil {
		if err := c.BPFWriter(key, d); err != nil {
			return err
		}
	}

	return nil
}

// Lookup retrieves a flow entry.
// Returns nil if the entry doesn't exist or has expired.
func (c *Cache) Lookup(key FlowKey) *FlowEntry {
	c.mu.RLock()
	entry, exists := c.entries[key]
	if !exists {
		c.mu.RUnlock()
		return nil
	}

	// Check TTL expiration
	if time.Since(entry.LastSeen) > c.ttl {
		c.mu.RUnlock()
		c.Delete(key)
		return nil
	}

	entry.HitCount++
	c.mu.RUnlock()
	return entry
}

// Delete removes a flow entry from the cache.
func (c *Cache) Delete(key FlowKey) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// evictLocked evicts the oldest entries when the cache is full.
// Must be called with c.mu held.
func (c *Cache) evictLocked() {
	if len(c.entries) < c.maxSize {
		return
	}

	// Remove 10% of oldest entries
	target := c.maxSize / 10
	if target < 1 {
		target = 1
	}

	// Find oldest entries by LastSeen
	type kv struct {
		key FlowKey
		val *FlowEntry
	}
	var oldest []kv
	for k, v := range c.entries {
		oldest = append(oldest, kv{k, v})
	}

	// Sort by LastSeen ascending (oldest first)
	for i := 0; i < len(oldest); i++ {
		for j := i + 1; j < len(oldest); j++ {
			if oldest[j].val.LastSeen.Before(oldest[i].val.LastSeen) {
				oldest[i], oldest[j] = oldest[j], oldest[i]
			}
		}
	}

	// Remove oldest entries
	for i := 0; i < target && i < len(oldest); i++ {
		delete(c.entries, oldest[i].key)
	}
}

// GC runs garbage collection, removing expired entries.
// Returns the number of entries removed.
func (c *Cache) GC() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0
	for key, entry := range c.entries {
		if now.Sub(entry.LastSeen) > c.ttl {
			delete(c.entries, key)
			removed++
		}
	}
	return removed
}

// Count returns the current number of entries in the cache.
func (c *Cache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// StartGC launches a background goroutine that runs GC periodically.
func (c *Cache) StartGC(interval time.Duration, stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				removed := c.GC()
				if removed > 0 {
					_ = removed // log if needed later
				}
			case <-stop:
				return
			}
		}
	}()
}
