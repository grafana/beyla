// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package xdp // import "go.opentelemetry.io/obi/pkg/internal/rdns/ebpf/xdp"

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../../../../bpf/rdns/rdns_xdp.c -- -I../../../../../bpf
