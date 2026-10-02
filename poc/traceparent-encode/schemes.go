package tpencode

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Result is one encoded traceparent.
type Result struct {
	Header    Header
	Value     string
	OriginKey [7]byte
	CallerKey [4]byte
}

// SplitHop is the only identity scheme: SHA-256 prefixes in the existing
// 24 W3C ID bytes.
//
//	trace-id [0:8]  = mix( {0xB1, digest[0:7]}, kdf(right) )
//	trace-id [8:16] = 8 random bytes
//	span-id  [0:4]  = digest[0:4] XOR rand32
//	span-id  [4:8]  = rand32
type SplitHop struct{}

func (SplitHop) Name() string { return "split-hop-hash" }

func (s SplitHop) Encode(origin, caller Identity) (Result, error) {
	var right [8]byte
	var spanRand [4]byte
	if _, err := rand.Read(right[:]); err != nil {
		return Result{}, err
	}
	if _, err := rand.Read(spanRand[:]); err != nil {
		return Result{}, err
	}
	return s.EncodeFixed(origin, caller, right, spanRand)
}

func (SplitHop) EncodeFixed(origin, caller Identity, right [8]byte, spanRand [4]byte) (Result, error) {
	plain := packOriginLeft(origin)
	var tid [16]byte
	left := xor8(plain, kdf8(right))
	copy(tid[:8], left[:])
	copy(tid[8:], right[:])

	sid := encodeCallerSpan(caller, spanRand)
	if allZero(tid[:]) || allZero(sid[:]) {
		return Result{}, fmt.Errorf("nonce produced an all-zero id")
	}

	h := Header{Version: 0, TraceID: tid, SpanID: sid, Flags: 1}
	return Result{
		Header:    h,
		Value:     Format(h),
		OriginKey: origin.OriginKey(),
		CallerKey: caller.CallerKey(),
	}, nil
}

func (SplitHop) Decode(value string, cat *Catalog) (origin, caller Identity, ok bool) {
	h, err := Parse(value)
	if err != nil {
		return Identity{}, Identity{}, false
	}
	origin, ok = decodeOrigin(h.TraceID, cat)
	if !ok {
		return Identity{}, Identity{}, false
	}
	caller = decodeCaller(h.SpanID, cat)
	return origin, caller, true
}

func packOriginLeft(origin Identity) [8]byte {
	var plain [8]byte
	plain[0] = schemeMagic
	k := origin.OriginKey()
	copy(plain[1:8], k[:])
	return plain
}

func decodeOrigin(tid [16]byte, cat *Catalog) (Identity, bool) {
	k, ok := parseOriginKey(tid)
	if !ok {
		return Identity{}, false
	}
	if id, hit := cat.LookupOrigin(k); hit {
		return id, true
	}
	return Identity{Name: "hash:" + key56Hex(k)}, true
}

func parseOriginKey(tid [16]byte) ([7]byte, bool) {
	var right8, left8 [8]byte
	copy(right8[:], tid[8:])
	copy(left8[:], tid[:8])
	plain := xor8(left8, kdf8(right8))
	var k [7]byte
	if plain[0] != schemeMagic {
		return k, false
	}
	copy(k[:], plain[1:8])
	return k, true
}

func encodeCallerSpan(caller Identity, spanRand [4]byte) [8]byte {
	var sid [8]byte
	copy(sid[4:], spanRand[:])
	k := caller.CallerKey()
	for i := range 4 {
		sid[i] = k[i] ^ sid[i+4]
	}
	return sid
}

func decodeCaller(sid [8]byte, cat *Catalog) Identity {
	var k [4]byte
	for i := range 4 {
		k[i] = sid[i] ^ sid[i+4]
	}
	id, unique, _ := cat.LookupCaller(k)
	if unique {
		return id
	}
	// Collision or unknown: do not guess. Catalog miss is the integrity
	// check that replaced crc8 — a random SDK span almost never hits.
	return Identity{}
}

// ---------------------------------------------------------------------------
// Suffix / RightPacked stay as negative evidence, not identity methods.
// ---------------------------------------------------------------------------

type Suffix struct {
	Version byte
}

func (s Suffix) Name() string { return fmt.Sprintf("suffix-v%02x", s.Version) }

func (s Suffix) Encode(origin, caller Identity) (Result, error) {
	var tid [16]byte
	var sid [8]byte
	if _, err := rand.Read(tid[:]); err != nil {
		return Result{}, err
	}
	if _, err := rand.Read(sid[:]); err != nil {
		return Result{}, err
	}
	extra := hex.EncodeToString([]byte(origin.String() + "\x1f" + caller.String()))
	h := Header{Version: s.Version, TraceID: tid, SpanID: sid, Flags: 1, Extra: extra}
	return Result{Header: h, Value: Format(h), OriginKey: origin.OriginKey(), CallerKey: caller.CallerKey()}, nil
}

type RightPacked struct{}

func (RightPacked) Name() string { return "right-packed-unsafe" }

func (RightPacked) Encode(origin, _ Identity) (Result, error) {
	var tid [16]byte
	if _, err := rand.Read(tid[:8]); err != nil {
		return Result{}, err
	}
	plain := packOriginLeft(origin)
	copy(tid[8:], plain[:])
	var sid [8]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return Result{}, err
	}
	if allZero(tid[:]) || allZero(sid[:]) {
		return RightPacked{}.Encode(origin, Identity{})
	}
	h := Header{Version: 0, TraceID: tid, SpanID: sid, Flags: 1}
	return Result{Header: h, Value: Format(h), OriginKey: origin.OriginKey()}, nil
}

func HeadSample(tid [16]byte, numerator, denominator uint32) bool {
	v := binary.BigEndian.Uint32(tid[12:])
	return v < uint32(uint64(numerator)<<32/uint64(denominator))
}
