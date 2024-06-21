package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"log/slog"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/grafana/beyla/pkg/internal/request"
)

func ReadGPUKernelLaunchIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	var event GPUKernelLaunchInfo
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
		return request.Span{}, true, err
	}

	// Log the GPU Kernel Launch event
	slog.Debug("GPU Kernel Launch", "event", event)

	return request.Span{
		Type: request.EventTypeGPUKernelLaunch,
	}, false, nil
}
