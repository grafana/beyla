package ebpfcommon

import (
	"bytes"
	"encoding/binary"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/grafana/beyla/pkg/internal/request"
)

func ReadGoKafkaRequestIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	var event GoKafkaClientInfo

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	if err != nil {
		return request.Span{}, true, err
	}

	// Do nothing for now
	// fmt.Printf("Received go kafka event\n")

	return request.Span{}, true, nil // ignore if we couldn't parse it
}
