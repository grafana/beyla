package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/grafana/beyla/pkg/internal/request"
	"golang.org/x/net/http2"
)

type BPFHTTP2Info bpfHttp2GrpcRequestT

func byteFramer(data []uint8) (*http2.Framer, *bytes.Buffer) {
	buf := bytes.NewBuffer(data)
	return http2.NewFramer(buf, buf), buf
}

func ReadHTTP2InfoIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	var event BPFHTTP2Info

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	if err != nil {
		return request.Span{}, true, err
	}

	_, b := byteFramer(event.Data[:])

	hf, err := http2.ReadFrameHeader(b)
	if err != nil {
		fmt.Printf("Got error reading frame %v\n", err)
		return request.Span{}, false, nil
	}

	fmt.Printf("type=%d, len=%d, stream_id=%d", hf.Type, hf.Length, hf.StreamID)

	return request.Span{}, false, nil
}
