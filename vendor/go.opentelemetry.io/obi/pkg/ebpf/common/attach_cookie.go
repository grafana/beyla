// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
)

var (
	hasAttachCookieOnce   sync.Once
	hasAttachCookieResult bool
)

// HasAttachCookie reports whether the running kernel exposes the
// bpf_get_attach_cookie helper (added in Linux 5.15). Result is cached for
// the lifetime of the process. Used by custom_span to gate cookie-based
// spec resolution behind a verifier-dead-code-eliminable constant.
func HasAttachCookie() bool {
	hasAttachCookieOnce.Do(func() {
		// Probe with Kprobe program type; uprobe / uretprobe share the
		// helper id and verifier path.
		hasAttachCookieResult = features.HaveProgramHelper(ebpf.Kprobe, asm.FnGetAttachCookie) == nil
	})
	return hasAttachCookieResult
}

var (
	hasUprobeRefCtrOffsetOnce   sync.Once
	hasUprobeRefCtrOffsetResult bool
)

// HasUprobeRefCtrOffset reports whether the uprobe PMU exposes the
// `ref_ctr_offset` format attribute (kernel ≥4.20). When this is absent,
// passing UprobeOptions.RefCtrOffset to cilium-ebpf is rejected with
// `RefCtrOffsetPMU not supported`, so callers should omit it on older
// kernels (e.g. RHEL 8 / 4.18 backports). Probes that gate their inline
// body on a non-zero semaphore (FOLLY_SDT_WITH_SEMAPHORE, the `usdt`
// crate) won't fire on these kernels because nothing bumps the counter,
// but the attach itself succeeds and other probes work.
func HasUprobeRefCtrOffset() bool {
	hasUprobeRefCtrOffsetOnce.Do(func() {
		// Mirrors cilium-ebpf's link/uprobe.go feature gate
		// (`/sys/bus/event_source/devices/uprobe/format/ref_ctr_offset`).
		_, err := os.Stat("/sys/bus/event_source/devices/uprobe/format/ref_ctr_offset")
		hasUprobeRefCtrOffsetResult = err == nil
	})
	return hasUprobeRefCtrOffsetResult
}
