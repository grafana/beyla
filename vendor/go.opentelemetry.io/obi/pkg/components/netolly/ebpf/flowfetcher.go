// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import "github.com/cilium/ebpf/ringbuf"

// this only exists to enable unit tests
type FlowFetcher interface {
	ReadInto(*ringbuf.Record) error
}
