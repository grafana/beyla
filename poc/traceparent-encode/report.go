package tpencode

import (
	"crypto/rand"
	"fmt"
	"io"
	"runtime"
	"strings"
)

func Report(w io.Writer) error {
	fmt.Fprintf(w, "traceparent identity sidecar — ARM POC evidence\n")
	fmt.Fprintf(w, "runtime: %s/%s\n\n", runtime.GOOS, runtime.GOARCH)

	printBudget(w)
	printBeylaConstants(w)
	printHashMethod(w)
	if err := printCollisionMath(w); err != nil {
		return err
	}
	if err := printRoundTrip(w); err != nil {
		return err
	}
	if err := printOTelInterop(w); err != nil {
		return err
	}
	if err := printSamplingBias(w); err != nil {
		return err
	}
	if err := printFalsePositives(w); err != nil {
		return err
	}
	if err := printHops(w); err != nil {
		return err
	}
	printTCPOption(w)
	printVerdict(w)
	return nil
}

func printBudget(w io.Writer) {
	fmt.Fprintln(w, "=== 1. Byte budget ===")
	fmt.Fprintln(w, "W3C v00 is 55 chars = 16-byte trace-id + 8-byte parent-id.")
	fmt.Fprintln(w, "Those 24 bytes are the only payload on HTTP/1, HPACK, and TCP option 25.")
	fmt.Fprintln(w, "Left 8 of trace-id = structure. Right 8 = uniqueness + sampling.")
	fmt.Fprintln(w, "Span-id is rewritten every hop = caller field.")
	fmt.Fprintln(w)
}

func printBeylaConstants(w io.Writer) {
	fmt.Fprintln(w, "=== 2. Beyla already pins the 55-char / 26-byte shape ===")
	fmt.Fprintf(w, "  TP_MAX_VAL_LENGTH=%d  HPACK val_len=%d  TCP option=%d/%d\n",
		W3CValueLen, HPACKValueLenTP, TCPOptionBytes, TCPOptionsMax)
	fmt.Fprintln(w, "  Extra ASCII suffix: OTel v00 Extract rejects; Inject strips v01 extras.")
	fmt.Fprintln(w)
}

func printHashMethod(w io.Writer) {
	fmt.Fprintln(w, "=== 3. Single method: SHA-256 prefix + catalog ===")
	fmt.Fprintln(w, "  digest = SHA-256(\"beyla.tpenc.v1\" || 0x00 || ns || 0x00 || name)")
	fmt.Fprintln(w, "  origin  = digest[0:7]  (56 bits) in trace-id left, XOR-mixed")
	fmt.Fprintln(w, "  caller  = digest[0:4]  (32 bits) in span-id, XOR-mixed")
	fmt.Fprintln(w, "  catalog = survey_info / discovery, keyed by those prefixes")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  No string packing. Name length is unlimited. Alphabet is unlimited.")
	fmt.Fprintln(w, "  Catalog membership is the integrity check (replaces crc8-on-span).")
	fmt.Fprintln(w, "  A 32-bit prefix that hits two catalog entries is refused, not guessed.")
	fmt.Fprintln(w)
}

func printCollisionMath(w io.Writer) error {
	fmt.Fprintln(w, "=== 4. Collision reduction ===")
	fmt.Fprintln(w, "  P(some pair collides) ≈ 1 - exp(-n(n-1) / 2^{bits+1})")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %-8s  %12s  %12s  %12s  %12s\n", "n", "24-bit", "32-bit", "48-bit", "56-bit")
	for _, n := range []int{100, 1_000, 10_000, 100_000, 1_000_000} {
		fmt.Fprintf(w, "  %-8d  %12s  %12s  %12s  %12s\n", n,
			pct(BirthdayProb(n, 24)),
			pct(BirthdayProb(n, 32)),
			pct(BirthdayProb(n, 48)),
			pct(BirthdayProb(n, 56)))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  24-bit (old caller+crc layout) is already coin-flip at 10k services.")
	fmt.Fprintln(w, "  32-bit caller: ~1.2% chance of some pair colliding at 10k; ~69% at 100k.")
	fmt.Fprintln(w, "  56-bit origin: negligible through a million services.")
	fmt.Fprintln(w, "  SHA-256 vs FNV: same width, better distribution, domain-separated.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  Handling: origin lookup is 56-bit exact. Caller lookup is 32-bit and")
	fmt.Fprintln(w, "  must be unique in the catalog. Ambiguity → drop the caller edge.")
	fmt.Fprintln(w, "  Phantom named caller given a catalog of size n: n / 2^32 per random span.")
	fmt.Fprintln(w)
	cat := NewCatalog(Corpus...)
	fmt.Fprintf(w, "  corpus size=%d  32-bit prefix collisions=%d\n", len(Corpus), cat.CallerCollisions())
	fmt.Fprintln(w)
	return nil
}

func pct(p float64) string {
	if p < 1e-12 {
		return "~0"
	}
	if p < 1e-4 {
		return fmt.Sprintf("%.2e", p)
	}
	return fmt.Sprintf("%.4f%%", 100*p)
}

func printRoundTrip(w io.Writer) error {
	fmt.Fprintln(w, "=== 5. Round-trip (legal W3C v00, any name length) ===")
	s := SplitHop{}
	cat := NewCatalog(Corpus...)
	shown := 0
	for _, id := range Corpus {
		res, err := s.Encode(id, id)
		if err != nil {
			return err
		}
		if err := W3CValid(res.Value); err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
		gotO, gotC, ok := s.Decode(res.Value, cat)
		if !ok || gotO != id || gotC != id {
			return fmt.Errorf("decode %s: origin=%s caller=%s", id, gotO, gotC)
		}
		if shown < 6 {
			fmt.Fprintf(w, "  %s\n    %s  origin=%s caller=%s\n", res.Value, id, key56Hex(res.OriginKey), key32Hex(res.CallerKey))
			shown++
		}
	}
	long := Identity{Namespace: "customer-prod", Name: strings.Repeat("worker", 30)}
	cat.Add(long)
	res, err := s.Encode(long, long)
	if err != nil {
		return err
	}
	gotO, _, ok := s.Decode(res.Value, cat)
	if !ok || gotO != long {
		return fmt.Errorf("long name failed")
	}
	fmt.Fprintf(w, "  long name (%d chars) also round-trips: %s\n", len(long.Name), res.Value)
	fmt.Fprintln(w)
	return nil
}

func printOTelInterop(w io.Writer) error {
	fmt.Fprintln(w, "=== 6. OTel Go propagator (v1.46.0 rules) ===")
	res, err := (SplitHop{}).Encode(Identity{Namespace: "prod", Name: "api"}, Identity{Namespace: "prod", Name: "api"})
	if err != nil {
		return err
	}
	_, otelOK := OTelExtract(res.Value)
	fmt.Fprintf(w, "  hash-loaded v00 (55 chars)  Extract=%v\n", otelOK)
	for _, c := range []struct {
		name string
		val  string
	}{
		{"v00 + suffix", mustSuffix(0)},
		{"v01 + suffix", mustSuffix(1)},
	} {
		extracted, ok := OTelExtract(c.val)
		fmt.Fprintf(w, "  %-22s Extract=%v\n", c.name, ok)
		if ok {
			fmt.Fprintf(w, "  %-22s Inject=%s\n", "", OTelInject(extracted))
		}
	}
	fmt.Fprintln(w)
	return nil
}

func mustSuffix(ver byte) string {
	r, err := (Suffix{Version: ver}).Encode(Identity{Namespace: "prod", Name: "api"}, Identity{Name: "worker"})
	if err != nil {
		panic(err)
	}
	return r.Value
}

func printSamplingBias(w io.Writer) error {
	fmt.Fprintln(w, "=== 7. Keep the hash on the LEFT of trace-id ===")
	const n = 4000
	id := Identity{Namespace: "prod", Name: "api"}
	leftHits, rightHits := 0, 0
	for range n {
		a, err := (SplitHop{}).Encode(id, id)
		if err != nil {
			return err
		}
		if HeadSample(a.Header.TraceID, 1, 10) {
			leftHits++
		}
		b, err := (RightPacked{}).Encode(id, id)
		if err != nil {
			return err
		}
		if HeadSample(b.Header.TraceID, 1, 10) {
			rightHits++
		}
	}
	fmt.Fprintf(w, "  10%% head-sampler, %d traces:\n", n)
	fmt.Fprintf(w, "    hash on LEFT (this scheme)  %.1f%%\n", 100*float64(leftHits)/float64(n))
	fmt.Fprintf(w, "    hash on RIGHT (unsafe)      %.1f%%\n", 100*float64(rightHits)/float64(n))
	fmt.Fprintln(w)
	return nil
}

func printFalsePositives(w io.Writer) error {
	fmt.Fprintln(w, "=== 8. Foreign IDs ===")
	const n = 200_000
	hits := 0
	for range n {
		var tid [16]byte
		if _, err := rand.Read(tid[:]); err != nil {
			return err
		}
		if _, ok := parseOriginKey(tid); ok {
			hits++
		}
	}
	fmt.Fprintf(w, "  random trace-id, magic 0xB1 after unmix: %d/%d  (expect ~1/256 = %d)\n",
		hits, n, n/256)

	id := Identity{Namespace: "prod", Name: "api"}
	cat := NewCatalog(id)
	res, err := (SplitHop{}).Encode(id, id)
	if err != nil {
		return err
	}
	phantoms := 0
	const nspan = 50_000
	for range nspan {
		var sid [8]byte
		if _, err := rand.Read(sid[:]); err != nil {
			return err
		}
		sid[7] |= 1
		h := res.Header
		h.SpanID = sid
		_, caller, _ := (SplitHop{}).Decode(Format(h), cat)
		if caller.Name != "" {
			phantoms++
		}
	}
	fmt.Fprintf(w, "  random span-id named by 1-entry catalog: %d/%d  (expect ~ n/2^32)\n", phantoms, nspan)
	fmt.Fprintln(w)
	return nil
}

func printHops(w io.Writer) error {
	fmt.Fprintln(w, "=== 9. A → B → C ===")
	s := SplitHop{}
	a := Identity{Namespace: "prod", Name: "api"}
	b := Identity{Namespace: "prod", Name: "worker"}
	c := Identity{Namespace: "prod", Name: "postgres"}
	cat := NewCatalog(a, b, c)

	ab, err := s.Encode(a, a)
	if err != nil {
		return err
	}
	bc, err := s.Encode(a, b)
	if err != nil {
		return err
	}
	bc.Header.TraceID = ab.Header.TraceID
	bc.Value = Format(bc.Header)

	o1, c1, _ := s.Decode(ab.Value, cat)
	o2, c2, _ := s.Decode(bc.Value, cat)
	fmt.Fprintf(w, "  A→B  %s\n    origin=%s  caller=%s\n", ab.Value, o1, c1)
	fmt.Fprintf(w, "  B→C  %s\n    origin=%s  caller=%s\n", bc.Value, o2, c2)

	var sdkSpan [8]byte
	if _, err := rand.Read(sdkSpan[:]); err != nil {
		return err
	}
	sdkSpan[7] |= 1
	sdk := Header{Version: 0, TraceID: bc.Header.TraceID, SpanID: sdkSpan, Flags: 1}
	o3, c3, ok := s.Decode(Format(sdk), cat)
	callerLabel := c3.String()
	if callerLabel == "" {
		callerLabel = "(not in catalog — SDK rewrite or unknown peer)"
	}
	fmt.Fprintf(w, "  after OTel Inject at B:\n    origin=%s  caller=%s  origin_ok=%v\n", o3, callerLabel, ok)
	fmt.Fprintln(w)
	return nil
}

func printTCPOption(w io.Writer) {
	fmt.Fprintln(w, "=== 10. TCP option still 26 bytes ===")
	fmt.Fprintf(w, "  kind 25 + len + 24 ID bytes. No growth. Hash fits in the bytes already sent.\n\n")
}

func printVerdict(w io.Writer) {
	fmt.Fprintln(w, "=== 11. Verdict ===")
	fmt.Fprintln(w, "  One method: SHA-256 prefix in the existing IDs, catalog binds names.")
	fmt.Fprintln(w, "  Spend bits on collision width, not on a symbol dictionary.")
	fmt.Fprintln(w, "  Origin 56-bit is the durable id. Caller 32-bit is unique-or-drop.")
	fmt.Fprintln(w, "  Userspace hashes once per process; BPF only copies 7+4 bytes.")
	fmt.Fprintln(w)
}

func DumpExample(w io.Writer, origin, caller Identity) error {
	res, err := (SplitHop{}).Encode(origin, caller)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "%s\n", res.Value)
	fmt.Fprintf(w, "origin=%s caller=%s\n", key56Hex(res.OriginKey), key32Hex(res.CallerKey))
	fmt.Fprintf(w, "trace_id=%x span_id=%x\n", res.Header.TraceID, res.Header.SpanID)
	return nil
}
