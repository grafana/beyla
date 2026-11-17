package freelru

import (
	"errors"
	"fmt"
	"math/bits"
	"runtime"
	"sync"
	"time"
)

// ShardedLRU is a thread-safe, sharded, fixed size LRU cache.
// Sharding is used to reduce lock contention on high concurrency.
// The downside is that exact LRU behavior is not given (as for the LRU and SynchedLRU types).
type ShardedLRU[K comparable, V any] struct {
	lrus   []LRU[K, V]
	mus    []sync.RWMutex
	hash   HashKeyCallback[K]
	shards uint32
	mask   uint32
}

var _ Cache[int, int] = (*ShardedLRU[int, int])(nil)

// SetLifetime sets the default lifetime of LRU elements.
// Lifetime 0 means "forever".
func (lru *ShardedLRU[K, V]) SetLifetime(lifetime time.Duration) {
	for shard := range lru.lrus {
		lru.mus[shard].Lock()
		lru.lrus[shard].SetLifetime(lifetime)
		lru.mus[shard].Unlock()
	}
}

// SetOnEvict sets the OnEvict callback function.
// The onEvict function is called for each evicted lru entry.
func (lru *ShardedLRU[K, V]) SetOnEvict(onEvict OnEvictCallback[K, V]) {
	for shard := range lru.lrus {
		lru.mus[shard].Lock()
		lru.lrus[shard].SetOnEvict(onEvict)
		lru.mus[shard].Unlock()
	}
}

func nextPowerOfTwo(val uint32) uint32 {
	if bits.OnesCount32(val) != 1 {
		return 1 << bits.Len32(val)
	}
	return val
}

// NewSharded creates a new thread-safe sharded LRU hashmap with the given capacity.
func NewSharded[K comparable, V any](capacity uint32, hash HashKeyCallback[K]) (*ShardedLRU[K, V],
	error) {
	size := uint32(float64(capacity) * 1.25) // 25% extra space for fewer collisions

	return NewShardedWithSize[K, V](uint32(runtime.GOMAXPROCS(0)*16), capacity, size, hash)
}

func NewShardedWithSize[K comparable, V any](shards, capacity, size uint32,
	hash HashKeyCallback[K]) (
	*ShardedLRU[K, V], error) {
	if capacity == 0 {
		return nil, errors.New("capacity must be positive")
	}
	if size < capacity {
		return nil, fmt.Errorf("size (%d) is smaller than capacity (%d)", size, capacity)
	}

	if size < 1<<31 {
		size = nextPowerOfTwo(size) // next power of 2 so the LRUs can avoid costly divisions
	} else {
		size = 1 << 31 // the highest 2^N value that fits in a uint32
	}

	shards = nextPowerOfTwo(shards) // next power of 2 so we can avoid costly division for sharding

	for shards > size/16 {
		shards /= 16
	}
	if shards == 0 {
		shards = 1
	}

	size /= shards // size per LRU
	if size == 0 {
		size = 1
	}

	capacity = (capacity + shards - 1) / shards // size per LRU
	if capacity == 0 {
		capacity = 1
	}

	lrus := make([]LRU[K, V], shards)
	buckets := make([]uint32, size*shards)
	elements := make([]element[K, V], size*shards)

	from := 0
	to := int(size)
	for i := range lrus {
		initLRU(&lrus[i], capacity, size, hash, buckets[from:to], elements[from:to])
		from = to
		to += int(size)
	}

	return &ShardedLRU[K, V]{
		lrus:   lrus,
		mus:    make([]sync.RWMutex, shards),
		hash:   hash,
		shards: shards,
		mask:   shards - 1,
	}, nil
}

// Len returns the number of elements stored in the cache.
func (lru *ShardedLRU[K, V]) Len() (length int) {
	for shard := range lru.lrus {
		lru.mus[shard].RLock()
		length += lru.lrus[shard].Len()
		lru.mus[shard].RUnlock()
	}
	return
}

// AddWithLifetime adds a key:value to the cache with a lifetime.
// Returns true, true if key was updated and eviction occurred.
func (lru *ShardedLRU[K, V]) AddWithLifetime(key K, value V,
	lifetime time.Duration) (evicted bool) {
	hash := lru.hash(key)
	shard := (hash >> 16) & lru.mask

	lru.mus[shard].Lock()
	evicted = lru.lrus[shard].addWithLifetime(hash, key, value, lifetime)
	lru.mus[shard].Unlock()

	return
}

// Add adds a key:value to the cache.
// Returns true, true if key was updated and eviction occurred.
func (lru *ShardedLRU[K, V]) Add(key K, value V) (evicted bool) {
	hash := lru.hash(key)
	shard := (hash >> 16) & lru.mask

	lru.mus[shard].Lock()
	evicted = lru.lrus[shard].add(hash, key, value)
	lru.mus[shard].Unlock()

	return
}

// Get returns the value associated with the key, setting it as the most
// recently used item.
// If the found cache item is already expired, the evict function is called
// and the return value indicates that the key was not found.
func (lru *ShardedLRU[K, V]) Get(key K) (value V, ok bool) {
	hash := lru.hash(key)
	shard := (hash >> 16) & lru.mask

	lru.mus[shard].Lock()
	value, ok = lru.lrus[shard].get(hash, key)
	lru.mus[shard].Unlock()

	return
}

// GetAndRefresh returns the value associated with the key, setting it as the most
// recently used item.
// The lifetime of the found cache item is refreshed, even if it was already expired.
func (lru *ShardedLRU[K, V]) GetAndRefresh(key K, lifetime time.Duration) (value V, ok bool) {
	hash := lru.hash(key)
	shard := (hash >> 16) & lru.mask

	lru.mus[shard].Lock()
	value, ok = lru.lrus[shard].getAndRefresh(hash, key, lifetime)
	lru.mus[shard].Unlock()

	return
}

// Peek looks up a key's value from the cache, without changing its recent-ness.
// If the found entry is already expired, the evict function is called.
func (lru *ShardedLRU[K, V]) Peek(key K) (value V, ok bool) {
	hash := lru.hash(key)
	shard := (hash >> 16) & lru.mask

	lru.mus[shard].Lock()
	value, ok = lru.lrus[shard].peek(hash, key)
	lru.mus[shard].Unlock()

	return
}

// Contains checks for the existence of a key, without changing its recent-ness.
// If the found entry is already expired, the evict function is called.
func (lru *ShardedLRU[K, V]) Contains(key K) (ok bool) {
	hash := lru.hash(key)
	shard := (hash >> 16) & lru.mask

	lru.mus[shard].Lock()
	ok = lru.lrus[shard].contains(hash, key)
	lru.mus[shard].Unlock()

	return
}

// Remove removes the key from the cache.
// The return value indicates whether the key existed or not.
// The evict function is called for the removed entry.
func (lru *ShardedLRU[K, V]) Remove(key K) (removed bool) {
	hash := lru.hash(key)
	shard := (hash >> 16) & lru.mask

	lru.mus[shard].Lock()
	removed = lru.lrus[shard].remove(hash, key)
	lru.mus[shard].Unlock()

	return
}

// RemoveOldest removes the oldest entry from the cache.
// Key, value and an indicator of whether the entry has been removed is returned.
// The evict function is called for the removed entry.
func (lru *ShardedLRU[K, V]) RemoveOldest() (key K, value V, removed bool) {
	hash := lru.hash(key)
	shard := (hash >> 16) & lru.mask

	lru.mus[shard].Lock()
	key, value, removed = lru.lrus[shard].RemoveOldest()
	lru.mus[shard].Unlock()

	return
}

// Keys returns a slice of the keys in the cache, from oldest to newest.
// Expired entries are not included.
// The evict function is called for each expired item.
func (lru *ShardedLRU[K, V]) Keys() []K {
	keys := make([]K, 0, lru.shards*lru.lrus[0].cap)
	for shard := range lru.lrus {
		lru.mus[shard].Lock()
		keys = append(keys, lru.lrus[shard].Keys()...)
		lru.mus[shard].Unlock()
	}

	return keys
}

// Purge purges all data (key and value) from the LRU.
// The evict function is called for each expired item.
// The LRU metrics are reset.
func (lru *ShardedLRU[K, V]) Purge() {
	for shard := range lru.lrus {
		lru.mus[shard].Lock()
		lru.lrus[shard].Purge()
		lru.mus[shard].Unlock()
	}
}

// PurgeExpired purges all expired items from the LRU.
// The evict function is called for each expired item.
func (lru *ShardedLRU[K, V]) PurgeExpired() {
	for shard := range lru.lrus {
		lru.mus[shard].Lock()
		lru.lrus[shard].PurgeExpired()
		lru.mus[shard].Unlock()
	}
}

// Metrics returns the metrics of the cache.
func (lru *ShardedLRU[K, V]) Metrics() Metrics {
	metrics := Metrics{}

	for shard := range lru.lrus {
		lru.mus[shard].Lock()
		m := lru.lrus[shard].Metrics()
		lru.mus[shard].Unlock()

		addMetrics(&metrics, m)
	}

	return metrics
}

// ResetMetrics resets the metrics of the cache and returns the previous state.
func (lru *ShardedLRU[K, V]) ResetMetrics() Metrics {
	metrics := Metrics{}

	for shard := range lru.lrus {
		lru.mus[shard].Lock()
		m := lru.lrus[shard].ResetMetrics()
		lru.mus[shard].Unlock()

		addMetrics(&metrics, m)
	}

	return metrics
}

func addMetrics(dst *Metrics, src Metrics) {
	dst.Inserts += src.Inserts
	dst.Collisions += src.Collisions
	dst.Evictions += src.Evictions
	dst.Removals += src.Removals
	dst.Hits += src.Hits
	dst.Misses += src.Misses
}

// just used for debugging
func (lru *ShardedLRU[K, V]) dump() {
	for shard := range lru.lrus {
		fmt.Printf("Shard %d:\n", shard)
		lru.mus[shard].RLock()
		lru.lrus[shard].dump()
		lru.mus[shard].RUnlock()
		fmt.Println("")
	}
}

func (lru *ShardedLRU[K, V]) PrintStats() {
	for shard := range lru.lrus {
		fmt.Printf("Shard %d:\n", shard)
		lru.mus[shard].RLock()
		lru.lrus[shard].PrintStats()
		lru.mus[shard].RUnlock()
		fmt.Println("")
	}
}
