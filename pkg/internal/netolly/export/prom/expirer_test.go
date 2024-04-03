package prom

import (
	"hash/fnv"
	"hash/maphash"
	"strings"
	"testing"
)

var lbls = []string{"asdfkjhdsfakl", "ksadlfjlk", "ksdlaf", "k3klj", "kdk", "kdsfjdlkjfd"}

func BenchmarkMapHash(b *testing.B) {
	m := map[uint64][]string{}
	for i := 0; i < b.N; i++ {
		h := maphash.Hash{}
		for _, l := range lbls {
			h.WriteString(l)
		}
		m[h.Sum64()] = lbls
	}
}

func BenchmarkFNV(b *testing.B) {
	m := map[uint64][]string{}
	for i := 0; i < b.N; i++ {
		h := fnv.New64()
		for _, l := range lbls {
			h.Write([]byte(l))
		}
		m[h.Sum64()] = lbls
	}
}

func BenchmarkJoin(b *testing.B) {
	m := map[string][]string{}
	for i := 0; i < b.N; i++ {
		m[strings.Join(lbls, ":")] = lbls
	}
}
