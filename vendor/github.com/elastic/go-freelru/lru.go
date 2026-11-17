// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package freelru

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"time"
)

// OnEvictCallback is the type for the eviction function.
type OnEvictCallback[K comparable, V any] func(K, V)

// HashKeyCallback is the function that creates a hash from the passed key.
type HashKeyCallback[K comparable] func(K) uint32

type element[K comparable, V any] struct {
	key   K
	value V

	// bucketNext and bucketPrev are indexes in the space-dimension doubly-linked list of elements.
	// That is to add/remove items to the collision bucket without re-allocations and with O(1)
	// complexity.
	// To simplify the implementation, internally a list l is implemented
	// as a ring, such that &l.latest.prev is last element and
	// &l.last.next is the latest element.
	nextBucket, prevBucket uint32

	// bucketPos is the bucket that an element belongs to.
	bucketPos uint32

	// next and prev are indexes in the time-dimension doubly-linked list of elements.
	// To simplify the implementation, internally a list l is implemented
	// as a ring, such that &l.latest.prev is last element and
	// &l.last.next is the latest element.
	next, prev uint32

	// expire is the point in time when the element expires.
	// Its value is Unix milliseconds since epoch.
	expire int64
}

const emptyBucket = math.MaxUint32

// LRU implements a non-thread safe fixed size LRU cache.
type LRU[K comparable, V any] struct {
	buckets  []uint32 // contains positions of bucket lists or 'emptyBucket'
	elements []element[K, V]
	onEvict  OnEvictCallback[K, V]
	hash     HashKeyCallback[K]
	lifetime time.Duration
	metrics  Metrics

	// used for element clearing after removal or expiration
	emptyKey   K
	emptyValue V

	head uint32 // index of the newest element in the cache
	len  uint32 // current number of elements in the cache
	cap  uint32 // max number of elements in the cache
	size uint32 // size of the element array (X% larger than cap)
	mask uint32 // bitmask to avoid the costly idiv in hashToPos() if size is a 2^n value
}

// Metrics contains metrics about the cache.
type Metrics struct {
	Inserts    uint64
	Collisions uint64
	Evictions  uint64
	Removals   uint64
	Hits       uint64
	Misses     uint64
}

var _ Cache[int, int] = (*LRU[int, int])(nil)

// SetLifetime sets the default lifetime of LRU elements.
// Lifetime 0 means "forever".
func (lru *LRU[K, V]) SetLifetime(lifetime time.Duration) {
	lru.lifetime = lifetime
}

// SetOnEvict sets the OnEvict callback function.
// The onEvict function is called for each evicted lru entry.
// Eviction happens
// - when the cache is full and a new entry is added (oldest entry is evicted)
// - when an entry is removed by Remove() or RemoveOldest()
// - when an entry is recognized as expired
// - when Purge() is called
func (lru *LRU[K, V]) SetOnEvict(onEvict OnEvictCallback[K, V]) {
	lru.onEvict = onEvict
}

// New constructs an LRU with the given capacity of elements.
// The hash function calculates a hash value from the keys.
func New[K comparable, V any](capacity uint32, hash HashKeyCallback[K]) (*LRU[K, V], error) {
	return NewWithSize[K, V](capacity, capacity, hash)
}

// NewWithSize constructs an LRU with the given capacity and size.
// The hash function calculates a hash value from the keys.
// A size greater than the capacity increases memory consumption and decreases the CPU consumption
// by reducing the chance of collisions.
// Size must not be lower than the capacity.
func NewWithSize[K comparable, V any](capacity, size uint32, hash HashKeyCallback[K]) (
	*LRU[K, V], error) {
	if capacity == 0 {
		return nil, errors.New("capacity must be positive")
	}
	if size == emptyBucket {
		return nil, fmt.Errorf("size must not be %#X", size)
	}
	if size < capacity {
		return nil, fmt.Errorf("size (%d) is smaller than capacity (%d)", size, capacity)
	}
	if hash == nil {
		return nil, errors.New("hash function must be set")
	}

	buckets := make([]uint32, size)
	elements := make([]element[K, V], size)

	var lru LRU[K, V]
	initLRU(&lru, capacity, size, hash, buckets, elements)

	return &lru, nil
}

func initLRU[K comparable, V any](lru *LRU[K, V], capacity, size uint32, hash HashKeyCallback[K],
	buckets []uint32, elements []element[K, V]) {
	lru.cap = capacity
	lru.size = size
	lru.hash = hash
	lru.buckets = buckets
	lru.elements = elements

	// If the size is 2^N, we can avoid costly divisions.
	if bits.OnesCount32(lru.size) == 1 {
		lru.mask = lru.size - 1
	}

	// Mark all slots as free.
	for i := range lru.buckets {
		lru.buckets[i] = emptyBucket
	}
}

// hashToBucketPos converts a hash value into a position in the elements array.
func (lru *LRU[K, V]) hashToBucketPos(hash uint32) uint32 {
	if lru.mask != 0 {
		return hash & lru.mask
	}
	return fastModulo(hash, lru.size)
}

// fastModulo calculates x % n without using the modulo operator (~4x faster).
// Reference: https://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
func fastModulo(x, n uint32) uint32 {
	return uint32((uint64(x) * uint64(n)) >> 32) //nolint:gosec
}

// hashToPos converts a key into a position in the elements array.
func (lru *LRU[K, V]) hashToPos(hash uint32) (bucketPos, elemPos uint32) {
	bucketPos = lru.hashToBucketPos(hash)
	elemPos = lru.buckets[bucketPos]
	return
}

// setHead links the element as the head into the list.
func (lru *LRU[K, V]) setHead(pos uint32) {
	// Both calls to setHead() check beforehand that pos != lru.head.
	// So if you run into this situation, you likely use FreeLRU in a concurrent situation
	// without proper locking. It requires a write lock, even around Get().
	// But better use SyncedLRU or SharedLRU in such a case.
	if pos == lru.head {
		panic(pos)
	}

	lru.elements[pos].prev = lru.head
	lru.elements[pos].next = lru.elements[lru.head].next
	lru.elements[lru.elements[lru.head].next].prev = pos
	lru.elements[lru.head].next = pos
	lru.head = pos
}

// unlinkElement removes the element from the elements list.
func (lru *LRU[K, V]) unlinkElement(pos uint32) {
	lru.elements[lru.elements[pos].prev].next = lru.elements[pos].next
	lru.elements[lru.elements[pos].next].prev = lru.elements[pos].prev
}

// unlinkBucket removes the element from the buckets list.
func (lru *LRU[K, V]) unlinkBucket(pos uint32) {
	prevBucket := lru.elements[pos].prevBucket
	nextBucket := lru.elements[pos].nextBucket
	if prevBucket == nextBucket && prevBucket == pos { //nolint:gocritic
		// The element references itself, so it's the only bucket entry
		lru.buckets[lru.elements[pos].bucketPos] = emptyBucket
		return
	}
	lru.elements[prevBucket].nextBucket = nextBucket
	lru.elements[nextBucket].prevBucket = prevBucket
	lru.buckets[lru.elements[pos].bucketPos] = nextBucket
}

// evict evicts the element at the given position.
func (lru *LRU[K, V]) evict(pos uint32) {
	if pos == lru.head {
		lru.head = lru.elements[pos].prev
	}

	lru.unlinkElement(pos)
	lru.unlinkBucket(pos)
	lru.len--

	if lru.onEvict != nil {
		// Save k/v for the eviction function.
		key := lru.elements[pos].key
		value := lru.elements[pos].value
		lru.onEvict(key, value)
	}
}

// Move element from position 'from' to position 'to'.
// That avoids 'gaps' and new elements can always be simply appended.
func (lru *LRU[K, V]) move(to, from uint32) {
	if to == from {
		return
	}
	if from == lru.head {
		lru.head = to
	}

	prev := lru.elements[from].prev
	next := lru.elements[from].next
	lru.elements[prev].next = to
	lru.elements[next].prev = to

	prev = lru.elements[from].prevBucket
	next = lru.elements[from].nextBucket
	lru.elements[prev].nextBucket = to
	lru.elements[next].prevBucket = to

	lru.elements[to] = lru.elements[from]

	if lru.buckets[lru.elements[to].bucketPos] == from {
		lru.buckets[lru.elements[to].bucketPos] = to
	}
}

// insert stores the k/v at pos.
// It updates the head to point to this position.
func (lru *LRU[K, V]) insert(pos uint32, key K, value V, lifetime time.Duration) {
	lru.elements[pos].key = key
	lru.elements[pos].value = value
	lru.elements[pos].expire = expire(lifetime)

	if lru.len == 0 {
		lru.elements[pos].prev = pos
		lru.elements[pos].next = pos
		lru.head = pos
	} else if pos != lru.head {
		lru.setHead(pos)
	}
	lru.len++
	lru.metrics.Inserts++
}

func now() int64 {
	return time.Now().UnixMilli()
}

func expire(lifetime time.Duration) int64 {
	if lifetime == 0 {
		return 0
	}
	return now() + lifetime.Milliseconds()
}

// clearKeyAndValue clears stale data to avoid memory leaks
func (lru *LRU[K, V]) clearKeyAndValue(pos uint32) {
	lru.elements[pos].key = lru.emptyKey
	lru.elements[pos].value = lru.emptyValue
}

func (lru *LRU[K, V]) findKey(hash uint32, key K) (uint32, bool) {
	_, startPos := lru.hashToPos(hash)
	if startPos == emptyBucket {
		return emptyBucket, false
	}

	pos := startPos
	for {
		if key == lru.elements[pos].key {
			if lru.elements[pos].expire != 0 && lru.elements[pos].expire <= now() {
				lru.removeAt(pos)
				return emptyBucket, false
			}
			return pos, true
		}

		pos = lru.elements[pos].nextBucket
		if pos == startPos {
			// Key not found
			return emptyBucket, false
		}
	}
}

func (lru *LRU[K, V]) findKeyNoExpire(hash uint32, key K) (uint32, bool) {
	_, startPos := lru.hashToPos(hash)
	if startPos == emptyBucket {
		return emptyBucket, false
	}

	pos := startPos
	for {
		if key == lru.elements[pos].key {
			return pos, true
		}

		pos = lru.elements[pos].nextBucket
		if pos == startPos {
			// Key not found
			return emptyBucket, false
		}
	}
}

// Len returns the number of elements stored in the cache.
func (lru *LRU[K, V]) Len() int {
	return int(lru.len)
}

// AddWithLifetime adds a key:value to the cache with a lifetime.
// Returns true, true if key was updated and eviction occurred.
func (lru *LRU[K, V]) AddWithLifetime(key K, value V, lifetime time.Duration) (evicted bool) {
	return lru.addWithLifetime(lru.hash(key), key, value, lifetime)
}

func (lru *LRU[K, V]) addWithLifetime(hash uint32, key K, value V,
	lifetime time.Duration) (evicted bool) {
	bucketPos, startPos := lru.hashToPos(hash)
	if startPos == emptyBucket {
		pos := lru.len

		if pos == lru.cap {
			// Capacity reached, evict the oldest entry and
			// store the new entry at evicted position.
			pos = lru.elements[lru.head].next
			lru.evict(pos)
			lru.metrics.Evictions++
			evicted = true
		}

		// insert new (first) entry into the bucket
		lru.buckets[bucketPos] = pos
		lru.elements[pos].bucketPos = bucketPos

		lru.elements[pos].nextBucket = pos
		lru.elements[pos].prevBucket = pos
		lru.insert(pos, key, value, lifetime)
		return evicted
	}

	// Walk through the bucket list to see whether key already exists.
	pos := startPos
	for {
		if lru.elements[pos].key == key {
			// Key exists, replace the value and update element to be the head element.
			lru.elements[pos].value = value
			lru.elements[pos].expire = expire(lifetime)

			if pos != lru.head {
				lru.unlinkElement(pos)
				lru.setHead(pos)
			}
			// count as insert, even if it's just an update
			lru.metrics.Inserts++
			return false
		}

		pos = lru.elements[pos].nextBucket
		if pos == startPos {
			// Key not found
			break
		}
	}

	pos = lru.len
	if pos == lru.cap {
		// Capacity reached, evict the oldest entry and
		// store the new entry at evicted position.
		pos = lru.elements[lru.head].next
		lru.evict(pos)
		lru.metrics.Evictions++
		evicted = true
		startPos = lru.buckets[bucketPos]
		if startPos == emptyBucket {
			startPos = pos
		}
	}

	// insert new entry into the existing bucket before startPos
	lru.buckets[bucketPos] = pos
	lru.elements[pos].bucketPos = bucketPos

	lru.elements[pos].nextBucket = startPos
	lru.elements[pos].prevBucket = lru.elements[startPos].prevBucket
	lru.elements[lru.elements[startPos].prevBucket].nextBucket = pos
	lru.elements[startPos].prevBucket = pos
	lru.insert(pos, key, value, lifetime)

	if lru.elements[pos].prevBucket != pos {
		// The bucket now contains more than 1 element.
		// That means we have a collision.
		lru.metrics.Collisions++
	}
	return evicted
}

// Add adds a key:value to the cache.
// Returns true, true if key was updated and eviction occurred.
func (lru *LRU[K, V]) Add(key K, value V) (evicted bool) {
	return lru.addWithLifetime(lru.hash(key), key, value, lru.lifetime)
}

func (lru *LRU[K, V]) add(hash uint32, key K, value V) (evicted bool) {
	return lru.addWithLifetime(hash, key, value, lru.lifetime)
}

// Get returns the value associated with the key, setting it as the most
// recently used item.
// If the found cache item is already expired, the evict function is called
// and the return value indicates that the key was not found.
func (lru *LRU[K, V]) Get(key K) (value V, ok bool) {
	return lru.get(lru.hash(key), key)
}

func (lru *LRU[K, V]) get(hash uint32, key K) (value V, ok bool) {
	if pos, ok := lru.findKey(hash, key); ok {
		if pos != lru.head {
			lru.unlinkElement(pos)
			lru.setHead(pos)
		}
		lru.metrics.Hits++
		return lru.elements[pos].value, ok
	}

	lru.metrics.Misses++
	return
}

// GetAndRefresh returns the value associated with the key, setting it as the most
// recently used item.
// The lifetime of the found cache item is refreshed, even if it was already expired.
func (lru *LRU[K, V]) GetAndRefresh(key K, lifetime time.Duration) (V, bool) {
	return lru.getAndRefresh(lru.hash(key), key, lifetime)
}

func (lru *LRU[K, V]) getAndRefresh(hash uint32, key K, lifetime time.Duration) (value V, ok bool) {
	if pos, ok := lru.findKeyNoExpire(hash, key); ok {
		if pos != lru.head {
			lru.unlinkElement(pos)
			lru.setHead(pos)
		}
		lru.metrics.Hits++
		lru.elements[pos].expire = expire(lifetime)
		return lru.elements[pos].value, ok
	}

	lru.metrics.Misses++
	return
}

// Peek looks up a key's value from the cache, without changing its recent-ness.
// If the found entry is already expired, the evict function is called.
func (lru *LRU[K, V]) Peek(key K) (value V, ok bool) {
	return lru.peek(lru.hash(key), key)
}

func (lru *LRU[K, V]) peek(hash uint32, key K) (value V, ok bool) {
	if pos, ok := lru.findKey(hash, key); ok {
		return lru.elements[pos].value, ok
	}

	return
}

// Contains checks for the existence of a key, without changing its recent-ness.
// If the found entry is already expired, the evict function is called.
func (lru *LRU[K, V]) Contains(key K) (ok bool) {
	_, ok = lru.peek(lru.hash(key), key)
	return
}

func (lru *LRU[K, V]) contains(hash uint32, key K) (ok bool) {
	_, ok = lru.peek(hash, key)
	return
}

// Remove removes the key from the cache.
// The return value indicates whether the key existed or not.
// The evict function is called for the removed entry.
func (lru *LRU[K, V]) Remove(key K) (removed bool) {
	return lru.remove(lru.hash(key), key)
}

func (lru *LRU[K, V]) remove(hash uint32, key K) (removed bool) {
	if pos, ok := lru.findKeyNoExpire(hash, key); ok {
		lru.removeAt(pos)
		return ok
	}

	return
}

func (lru *LRU[K, V]) removeAt(pos uint32) {
	lru.evict(pos)
	lru.move(pos, lru.len)
	lru.metrics.Removals++

	// remove stale data to avoid memory leaks
	lru.clearKeyAndValue(lru.len)
}

// RemoveOldest removes the oldest entry from the cache.
// Key, value and an indicator of whether the entry has been removed is returned.
// The evict function is called for the removed entry.
func (lru *LRU[K, V]) RemoveOldest() (key K, value V, removed bool) {
	if lru.len == 0 {
		return lru.emptyKey, lru.emptyValue, false
	}
	pos := lru.elements[lru.head].next
	key = lru.elements[pos].key
	value = lru.elements[pos].value
	lru.removeAt(pos)
	return key, value, true
}

// Keys returns a slice of the keys in the cache, from oldest to newest.
// Expired entries are not included.
// The evict function is called for each expired item.
func (lru *LRU[K, V]) Keys() []K {
	lru.PurgeExpired()

	keys := make([]K, 0, lru.len)
	pos := lru.elements[lru.head].next
	for i := uint32(0); i < lru.len; i++ {
		keys = append(keys, lru.elements[pos].key)
		pos = lru.elements[pos].next
	}
	return keys
}

// Purge purges all data (key and value) from the LRU.
// The evict function is called for each expired item.
// The LRU metrics are reset.
func (lru *LRU[K, V]) Purge() {
	l := lru.len
	for i := uint32(0); i < l; i++ {
		_, _, _ = lru.RemoveOldest()
	}

	lru.metrics = Metrics{}
}

// PurgeExpired purges all expired items from the LRU.
// The evict function is called for each expired item.
func (lru *LRU[K, V]) PurgeExpired() {
	l := lru.len
	for i := uint32(0); i < l; i++ {
		pos := lru.elements[lru.head].next
		if lru.elements[pos].expire != 0 {
			if lru.elements[pos].expire > now() {
				return // no more expired items
			}
			lru.removeAt(pos)
		}
	}
}

// Metrics returns the metrics of the cache.
func (lru *LRU[K, V]) Metrics() Metrics {
	return lru.metrics
}

// ResetMetrics resets the metrics of the cache and returns the previous state.
func (lru *LRU[K, V]) ResetMetrics() Metrics {
	metrics := lru.metrics
	lru.metrics = Metrics{}
	return metrics
}

// just used for debugging
func (lru *LRU[K, V]) dump() {
	fmt.Printf("head %d len %d cap %d size %d mask 0x%X\n",
		lru.head, lru.len, lru.cap, lru.size, lru.mask)

	for i := range lru.buckets {
		if lru.buckets[i] == emptyBucket {
			continue
		}
		fmt.Printf("  bucket[%d] -> %d\n", i, lru.buckets[i])
		pos := lru.buckets[i]
		for {
			e := &lru.elements[pos]
			fmt.Printf("    pos %d bucketPos %d prevBucket %d nextBucket %d prev %d next %d k %v v %v\n",
				pos, e.bucketPos, e.prevBucket, e.nextBucket, e.prev, e.next, e.key, e.value)
			pos = e.nextBucket
			if pos == lru.buckets[i] {
				break
			}
		}
	}
}

func (lru *LRU[K, V]) PrintStats() {
	m := &lru.metrics
	fmt.Printf("Inserts: %d Collisions: %d (%.2f%%) Evictions: %d Removals: %d Hits: %d (%.2f%%) Misses: %d\n",
		m.Inserts, m.Collisions, float64(m.Collisions)/float64(m.Inserts)*100,
		m.Evictions, m.Removals,
		m.Hits, float64(m.Hits)/float64(m.Hits+m.Misses)*100, m.Misses)
}
