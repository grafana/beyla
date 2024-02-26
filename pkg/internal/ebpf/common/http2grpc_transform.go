package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/grafana/beyla/pkg/internal/request"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type BPFHTTP2Info bpfHttp2GrpcRequestT

func byteFramer(data []uint8) (*http2.Framer, *bytes.Buffer) {
	buf := bytes.NewBuffer(data)
	fr := http2.NewFramer(buf, buf)

	return fr, buf
}

func readMetaFrame(fr *http2.Framer, hf *http2.HeadersFrame) (string, string) {
	method := ""
	path := ""

	hdec := hpack.NewDecoder(0, nil)
	hdec.SetMaxStringLength(4096)
	hdec.SetEmitFunc(func(hf hpack.HeaderField) {
		fmt.Printf("AAAA %s\n", hf.Name)
		hfKey := strings.ToLower(hf.Name)
		switch hfKey {
		case ":method":
			method = hf.Value
		case ":path":
			path = hf.Value
		}
	})
	// Lose reference to MetaHeadersFrame:
	defer hdec.SetEmitFunc(func(hf hpack.HeaderField) {})

	for {
		frag := hf.HeaderBlockFragment()
		if _, err := hdec.Write(frag); err != nil {
			return method, path
		}

		if hf.HeadersEnded() {
			break
		}
		if _, err := fr.ReadFrame(); err != nil {
			return method, path
		}
	}

	return method, path
}

func ReadHTTP2InfoIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	var event BPFHTTP2Info

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	if err != nil {
		return request.Span{}, true, err
	}

	framer, _ := byteFramer(event.Data[:])

	f, _ := framer.ReadFrame()

	switch ff := f.(type) {
	case *http2.HeadersFrame:
		method, path := readMetaFrame(framer, ff)
		fmt.Printf("HTTP2/gRPC method %s path %s\n", method, path)
	}

	// if err != nil {
	// 	fmt.Printf("Got error reading frame data %v\n", err)
	// 	return request.Span{}, false, nil
	// }

	// if f != nil {
	// 	fmt.Printf("Frame: type = %d, stream_id = %d, len = %d\n", f.Header().Type, f.Header().StreamID, f.Header().Length)
	// }

	return request.Span{}, false, nil
}
