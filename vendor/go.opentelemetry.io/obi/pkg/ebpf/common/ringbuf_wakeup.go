// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

const ringBufRecordHdrSize = 8

func WakeupDataBytes(wakeupLen int, eventSize uintptr, ringBufSize uint32) uint32 {
	if wakeupLen <= 1 {
		return 0
	}
	maxWakeupDataBytes := uint64(ringBufSize) / 2
	recordSize := uint64(eventSize) + ringBufRecordHdrSize
	if uint64(wakeupLen) > maxWakeupDataBytes/recordSize {
		return uint32(maxWakeupDataBytes)
	}
	return uint32(uint64(wakeupLen) * recordSize)
}
