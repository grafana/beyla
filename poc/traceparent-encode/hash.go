package tpencode

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"
	"strings"
)

const (
	// 0xB1 = loaded v1, hash-only. One scheme, no string packing.
	schemeMagic byte = 0xB1

	hashDomain = "beyla.tpenc.v1"
)

// Identity is service_namespace + service_name. The wire never carries the
// strings; it carries prefixes of IdentityDigest.
type Identity struct {
	Namespace string
	Name      string
}

func (id Identity) String() string {
	if id.Namespace == "" {
		return id.Name
	}
	return id.Namespace + "/" + id.Name
}

func normalizeIdent(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// IdentityDigest is SHA-256("beyla.tpenc.v1" || 0x00 || ns || 0x00 || name).
// Origin uses digest[0:7] (56 bits). Caller uses digest[0:4] (32 bits).
// Same digest, different widths: a 32-bit caller hit can be confirmed against
// the 56-bit origin when both are present, and catalog prefix-ambiguity is
// detectable.
func IdentityDigest(namespace, name string) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(hashDomain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(normalizeIdent(namespace)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(normalizeIdent(name)))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (id Identity) Digest() [32]byte {
	return IdentityDigest(id.Namespace, id.Name)
}

func (id Identity) OriginKey() [7]byte {
	var k [7]byte
	d := id.Digest()
	copy(k[:], d[:7])
	return k
}

func (id Identity) CallerKey() [4]byte {
	var k [4]byte
	d := id.Digest()
	copy(k[:], d[:4])
	return k
}

func key56Hex(k [7]byte) string { return hex.EncodeToString(k[:]) }
func key32Hex(k [4]byte) string { return hex.EncodeToString(k[:]) }

func key32u(k [4]byte) uint32 { return binary.BigEndian.Uint32(k[:]) }

// Catalog is the discovery plane: digest prefix → (namespace, name).
// It is also the collision detector. A 32-bit caller key that maps to two
// services is refused rather than guessed.
type Catalog struct {
	by56 map[[7]byte]Identity
	by32 map[[4]byte][]Identity
}

func NewCatalog(ids ...Identity) *Catalog {
	c := &Catalog{
		by56: map[[7]byte]Identity{},
		by32: map[[4]byte][]Identity{},
	}
	for _, id := range ids {
		c.Add(id)
	}
	return c
}

func (c *Catalog) Add(id Identity) {
	if c.by56 == nil {
		c.by56 = map[[7]byte]Identity{}
		c.by32 = map[[4]byte][]Identity{}
	}
	k56 := id.OriginKey()
	k32 := id.CallerKey()
	c.by56[k56] = id
	for _, existing := range c.by32[k32] {
		if existing == id {
			return
		}
	}
	c.by32[k32] = append(c.by32[k32], id)
}

func (c *Catalog) LookupOrigin(k [7]byte) (Identity, bool) {
	if c == nil {
		return Identity{}, false
	}
	id, ok := c.by56[k]
	return id, ok
}

// LookupCaller returns the identity only when exactly one catalog entry shares
// the 32-bit prefix. Two hits is a collision: unique=false, id empty.
func (c *Catalog) LookupCaller(k [4]byte) (id Identity, unique bool, n int) {
	if c == nil {
		return Identity{}, false, 0
	}
	hits := c.by32[k]
	switch len(hits) {
	case 1:
		return hits[0], true, 1
	default:
		return Identity{}, false, len(hits)
	}
}

func (c *Catalog) CallerCollisions() int {
	if c == nil {
		return 0
	}
	n := 0
	for _, hits := range c.by32 {
		if len(hits) > 1 {
			n++
		}
	}
	return n
}

// BirthdayProb is 1 - exp(-n(n-1) / 2^{bits+1}), the chance that some pair
// among n random keys collides.
func BirthdayProb(n, bits int) float64 {
	if n < 2 || bits <= 0 {
		return 0
	}
	pairs := float64(n) * float64(n-1) / 2
	space := math.Ldexp(1, bits)
	if pairs/space > 40 {
		return 1
	}
	p := 1 - math.Exp(-pairs/space)
	if p < 0 {
		return 0
	}
	if p > 1 {
		return 1
	}
	return p
}

func fnv32(p []byte) uint32 {
	var h uint32 = 2166136261
	for _, v := range p {
		h ^= uint32(v)
		h *= 16777619
	}
	return h
}

func kdf8(right [8]byte) [8]byte {
	a := fnv32(right[:])
	tmp := right
	tmp[0] ^= 0x5a
	b := fnv32(tmp[:])
	return [8]byte{
		byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a),
		byte(b >> 24), byte(b >> 16), byte(b >> 8), byte(b),
	}
}

func xor8(a, b [8]byte) [8]byte {
	var out [8]byte
	for i := range 8 {
		out[i] = a[i] ^ b[i]
	}
	return out
}
