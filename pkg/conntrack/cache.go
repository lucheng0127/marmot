package conntrack

import (
	"sync"
	"time"
)

// CacheKey — 纯目标 key（路由决策仅基于目标地址）
// SrcIP / SrcPort 不参与决策，因此不在 cache key 中。
type CacheKey struct {
	DstIP    uint32
	DstPort  uint16
	Protocol uint8
}

// CacheEntry — 缓存的决策结果
type CacheEntry struct {
	Decision Decision // Direct / Proxy
	LastSeen time.Time
	HitCount uint64
}

// Decision — 简化决策结果
type Decision uint8

const (
	DecisionDirect Decision = iota
	DecisionProxy
)

// Cache — 用户态 Decision Cache，线程安全，纯目标 key
type Cache struct {
	mu      sync.RWMutex
	entries map[CacheKey]*CacheEntry
	ttl     time.Duration
	maxSize int
}

// New 创建用户态 Decision Cache
func New(ttl time.Duration, maxSize int) *Cache {
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	if maxSize <= 0 {
		maxSize = 65536
	}
	return &Cache{
		entries: make(map[CacheKey]*CacheEntry),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

// Insert 添加或更新缓存条目
func (c *Cache) Insert(key CacheKey, d uint8) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.entries[key]
	now := time.Now()
	if exists {
		entry.Decision = Decision(d)
		entry.LastSeen = now
		entry.HitCount++
	} else {
		if len(c.entries) >= c.maxSize {
			c.evictLocked()
		}
		c.entries[key] = &CacheEntry{
			Decision: Decision(d),
			LastSeen: now,
			HitCount: 1,
		}
	}
}

// Lookup 查询缓存，返回缓存的决策和命中计数
// 如果不存在或已过期，返回 DecisionProxy 作为默认值
func (c *Cache) Lookup(key CacheKey) (Decision, uint64, bool) {
	c.mu.RLock()
	entry, exists := c.entries[key]
	if !exists {
		c.mu.RUnlock()
		return DecisionProxy, 0, false
	}
	if time.Since(entry.LastSeen) > c.ttl {
		c.mu.RUnlock()
		c.Delete(key)
		return DecisionProxy, 0, false
	}
	entry.HitCount++
	d := entry.Decision
	hc := entry.HitCount
	c.mu.RUnlock()
	return d, hc, true
}

// Delete 删除缓存条目
func (c *Cache) Delete(key CacheKey) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

// evictLocked 淘汰最旧条目（满时）
func (c *Cache) evictLocked() {
	if len(c.entries) < c.maxSize {
		return
	}
	target := c.maxSize / 10
	if target < 1 {
		target = 1
	}
	type kv struct {
		key CacheKey
		val *CacheEntry
	}
	var oldest []kv
	for k, v := range c.entries {
		oldest = append(oldest, kv{k, v})
	}
	for i := 0; i < len(oldest); i++ {
		for j := i + 1; j < len(oldest); j++ {
			if oldest[j].val.LastSeen.Before(oldest[i].val.LastSeen) {
				oldest[i], oldest[j] = oldest[j], oldest[i]
			}
		}
	}
	for i := 0; i < target && i < len(oldest); i++ {
		delete(c.entries, oldest[i].key)
	}
}

// GC 清理过期条目
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

// Count 返回当前条目数
func (c *Cache) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// StartGC 启动后台 GC
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

// Stats 返回缓存统计
func (c *Cache) Stats() (int, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	total := len(c.entries)
	hits := 0
	for _, e := range c.entries {
		hits += int(e.HitCount)
	}
	return total, hits
}
