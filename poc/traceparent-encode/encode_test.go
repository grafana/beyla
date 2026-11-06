package tpencode

import (
	"crypto/rand"
	"strings"
	"testing"
)

func TestDigestStableAndCaseFolded(t *testing.T) {
	a := IdentityDigest("prod", "api")
	b := IdentityDigest("PROD", "API")
	if a != b {
		t.Fatal("digest must be case-insensitive")
	}
	if a == ([32]byte{}) {
		t.Fatal("digest must be non-zero")
	}
	c := IdentityDigest("prod", "web")
	if a == c {
		t.Fatal("different names must not share a digest")
	}
}

func TestNoLengthLimit(t *testing.T) {
	id := Identity{
		Namespace: "customer-prod",
		Name:      strings.Repeat("order-processing-worker-", 20),
	}
	cat := NewCatalog(id)
	res, err := (SplitHop{}).Encode(id, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := W3CValid(res.Value); err != nil {
		t.Fatal(err)
	}
	gotO, gotC, ok := (SplitHop{}).Decode(res.Value, cat)
	if !ok || gotO != id || gotC != id {
		t.Fatalf("long name: origin=%s caller=%s ok=%v", gotO, gotC, ok)
	}
}

func TestSplitHopW3CAndOTel(t *testing.T) {
	s := SplitHop{}
	cat := NewCatalog(Corpus...)
	if n := cat.CallerCollisions(); n != 0 {
		t.Fatalf("corpus has %d 32-bit caller collisions", n)
	}
	for _, id := range Corpus {
		res, err := s.Encode(id, id)
		if err != nil {
			t.Fatal(err)
		}
		if err := W3CValid(res.Value); err != nil {
			t.Fatalf("%s: %v (%s)", id, err, res.Value)
		}
		if _, ok := OTelExtract(res.Value); !ok {
			t.Fatalf("OTel rejected %s", res.Value)
		}
		gotO, gotC, ok := s.Decode(res.Value, cat)
		if !ok || gotO != id || gotC != id {
			t.Fatalf("decode %s: origin=%s caller=%s ok=%v", id, gotO, gotC, ok)
		}
	}
}

func TestOTelRejectsV00Suffix(t *testing.T) {
	res, err := (Suffix{Version: 0}).Encode(Identity{Name: "api"}, Identity{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := OTelExtract(res.Value); ok {
		t.Fatalf("v00 suffix must be rejected: %s", res.Value)
	}
}

func TestOTelAcceptsV01SuffixThenStrips(t *testing.T) {
	res, err := (Suffix{Version: 1}).Encode(Identity{Namespace: "prod", Name: "api"}, Identity{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := OTelExtract(res.Value)
	if !ok || got.Extra == "" {
		t.Fatal("v01 suffix must extract with leftover")
	}
	injected := OTelInject(got)
	if err := W3CValid(injected); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(injected, got.Extra) || !strings.HasPrefix(injected, "00-") {
		t.Fatalf("inject must drop extra and downgrade: %s", injected)
	}
}

func TestOriginMagicFalsePositive(t *testing.T) {
	const n = 50_000
	hits := 0
	for range n {
		var tid [16]byte
		if _, err := rand.Read(tid[:]); err != nil {
			t.Fatal(err)
		}
		if _, ok := parseOriginKey(tid); ok {
			hits++
		}
	}
	// magic 0xB1 is 1/256. Allow 4x slack.
	if hits > n/64 {
		t.Fatalf("origin magic false positives %d/%d", hits, n)
	}
}

func TestHeadSamplerUnbiasedOnSplitHop(t *testing.T) {
	const n = 3000
	id := Identity{Namespace: "prod", Name: "api"}
	hits := 0
	for range n {
		res, err := (SplitHop{}).Encode(id, id)
		if err != nil {
			t.Fatal(err)
		}
		if HeadSample(res.Header.TraceID, 1, 10) {
			hits++
		}
	}
	rate := float64(hits) / float64(n)
	if rate < 0.05 || rate > 0.15 {
		t.Fatalf("sample rate %.2f outside 5-15%%", rate)
	}
}

func TestHeadSamplerBiasedOnRightPack(t *testing.T) {
	id := Identity{Namespace: "prod", Name: "api"}
	a, err := (RightPacked{}).Encode(id, id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := (RightPacked{}).Encode(id, id)
	if err != nil {
		t.Fatal(err)
	}
	if a.Header.TraceID[12] != b.Header.TraceID[12] ||
		a.Header.TraceID[13] != b.Header.TraceID[13] ||
		a.Header.TraceID[14] != b.Header.TraceID[14] ||
		a.Header.TraceID[15] != b.Header.TraceID[15] {
		t.Fatal("right-packed last 32 bits should be identical for one service")
	}
}

func TestHopKeepsOrigin(t *testing.T) {
	s := SplitHop{}
	a := Identity{Namespace: "prod", Name: "api"}
	b := Identity{Namespace: "prod", Name: "worker"}
	cat := NewCatalog(a, b)

	ab, err := s.Encode(a, a)
	if err != nil {
		t.Fatal(err)
	}
	bc, err := s.Encode(a, b)
	if err != nil {
		t.Fatal(err)
	}
	bc.Header.TraceID = ab.Header.TraceID
	bc.Value = Format(bc.Header)

	o1, c1, ok := s.Decode(ab.Value, cat)
	if !ok || o1 != a || c1 != a {
		t.Fatalf("A→B: origin=%s caller=%s", o1, c1)
	}
	o2, c2, ok := s.Decode(bc.Value, cat)
	if !ok || o2 != a || c2 != b {
		t.Fatalf("B→C: origin=%s caller=%s", o2, c2)
	}
}

func TestSDKSpanDoesNotInventCaller(t *testing.T) {
	id := Identity{Namespace: "prod", Name: "api"}
	cat := NewCatalog(id)
	res, err := (SplitHop{}).Encode(id, id)
	if err != nil {
		t.Fatal(err)
	}
	hits := 0
	for range 4000 {
		var sid [8]byte
		if _, err := rand.Read(sid[:]); err != nil {
			t.Fatal(err)
		}
		sid[7] |= 1
		h := res.Header
		h.SpanID = sid
		_, caller, ok := (SplitHop{}).Decode(Format(h), cat)
		if !ok {
			t.Fatal("origin must still decode")
		}
		if caller != (Identity{}) {
			hits++
		}
	}
	// Catalog-gated 32-bit key: 4000/2^32 ≈ 0.0000009 expected hits.
	if hits != 0 {
		t.Fatalf("phantom callers %d/4000", hits)
	}
}

func TestCallerPrefixCollisionRefused(t *testing.T) {
	a := Identity{Name: "alpha"}
	b := Identity{Name: "beta"}
	cat := NewCatalog(a)
	// Force a 32-bit prefix collision without needing a SHA-256 break.
	cat.by32[a.CallerKey()] = append(cat.by32[a.CallerKey()], b)
	if cat.CallerCollisions() != 1 {
		t.Fatal("expected one colliding prefix")
	}

	res, err := (SplitHop{}).Encode(a, a)
	if err != nil {
		t.Fatal(err)
	}
	gotO, gotC, ok := (SplitHop{}).Decode(res.Value, cat)
	if !ok || gotO != a {
		t.Fatalf("origin should still resolve at 56 bits: %s ok=%v", gotO, ok)
	}
	if gotC != (Identity{}) {
		t.Fatalf("caller must be refused on 32-bit ambiguity, got %s", gotC)
	}
}

func TestUnknownCallerNotNamed(t *testing.T) {
	known := Identity{Name: "nginx"}
	unknown := Identity{Name: "sshd"}
	cat := NewCatalog(known)
	res, err := (SplitHop{}).Encode(known, unknown)
	if err != nil {
		t.Fatal(err)
	}
	_, gotC, ok := (SplitHop{}).Decode(res.Value, cat)
	if !ok {
		t.Fatal("origin should decode")
	}
	if gotC != (Identity{}) {
		t.Fatalf("unknown caller must not be named, got %s", gotC)
	}
}

func TestCInteropVector(t *testing.T) {
	var right = [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	var span = [4]byte{0xde, 0xad, 0xbe, 0xef}
	res, err := (SplitHop{}).EncodeFixed(
		Identity{Namespace: "prod", Name: "api"},
		Identity{Namespace: "prod", Name: "api"},
		right, span)
	if err != nil {
		t.Fatal(err)
	}
	if err := W3CValid(res.Value); err != nil {
		t.Fatal(err)
	}
	const want = "00-429c4fa371e4e8240123456789abcdef-7df3987bdeadbeef-01"
	if res.Value != want {
		t.Fatalf("C/Go vector drifted\n got %s\nwant %s", res.Value, want)
	}
	if key56Hex(res.OriginKey) != "a35e269406e3ab" || key32Hex(res.CallerKey) != "a35e2694" {
		t.Fatalf("keys drifted origin=%s caller=%s", key56Hex(res.OriginKey), key32Hex(res.CallerKey))
	}
}

func TestBirthdayMath(t *testing.T) {
	// Sanity: 10k keys in 24 bits is almost sure to collide; in 56 bits is not.
	if BirthdayProb(10_000, 24) < 0.9 {
		t.Fatalf("24-bit/10k should be near-certain, got %v", BirthdayProb(10_000, 24))
	}
	if BirthdayProb(10_000, 56) > 1e-9 {
		t.Fatalf("56-bit/10k should be ~0, got %v", BirthdayProb(10_000, 56))
	}
}
