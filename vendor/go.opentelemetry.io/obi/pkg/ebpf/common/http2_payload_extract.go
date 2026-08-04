// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http2"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/bhpack"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

const (
	maxHTTP1RequestLineScan = 8 << 10
	maxHTTP2ReadFrameSize   = 1 << 20
)

var http1RequestLineMarker = []byte(" HTTP/1.")

func looksLikeHTTP1Request(buffer *largebuf.LargeBuffer) bool {
	n := min(buffer.Len(), maxHTTP1RequestLineScan)
	if n <= 0 {
		return false
	}

	reader := buffer.NewReader()
	head, err := reader.Peek(n)
	if err != nil {
		return false
	}

	if nl := bytes.IndexByte(head, '\n'); nl >= 0 {
		head = head[:nl]
	}

	return bytes.Contains(head, http1RequestLineMarker)
}

func parseHTTP2Request(buffer *largebuf.LargeBuffer, span *request.Span) (*http.Request, bool) {
	body, header, ok := extractHTTP2(buffer)
	if !ok {
		return nil, false
	}

	req := &http.Request{
		Method:        span.Method,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        header,
		Host:          span.Host,
		URL:           &url.URL{Path: span.Path, Host: span.Host},
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}

	return req, true
}

var http1ResponseMarker = []byte("HTTP/1.")

func looksLikeHTTP1Response(buffer *largebuf.LargeBuffer) bool {
	if buffer.Len() < len(http1ResponseMarker) {
		return false
	}

	reader := buffer.NewReader()
	head, err := reader.Peek(len(http1ResponseMarker))
	if err != nil {
		return false
	}

	return bytes.Equal(head, http1ResponseMarker)
}

func parseHTTP2Response(buffer *largebuf.LargeBuffer, req *http.Request, span *request.Span) (*http.Response, bool) {
	body, header, ok := extractHTTP2(buffer)
	if !ok {
		return nil, false
	}

	if header.Get("Content-Encoding") == "" {
		if enc := sniffContentEncoding(body); enc != "" {
			header.Set("Content-Encoding", enc)
		}
	}

	resp := &http.Response{
		StatusCode:    span.Status,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}

	return resp, true
}

func sniffContentEncoding(body []byte) string {
	switch {
	case len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b:
		return "gzip"
	case len(body) >= 4 && body[0] == 0x28 && body[1] == 0xb5 && body[2] == 0x2f && body[3] == 0xfd:
		return "zstd"
	default:
		return ""
	}
}

func extractHTTP2(buffer *largebuf.LargeBuffer) ([]byte, http.Header, bool) {
	reader := buffer.NewReader()

	// Skip the preface when present
	if pre, err := reader.Peek(len(http2.ClientPreface)); err == nil &&
		string(pre) == http2.ClientPreface {
		_ = reader.Skip(len(http2.ClientPreface))
	}

	framer := http2.NewFramer(io.Discard, &reader)
	framer.SetMaxReadFrameSize(maxHTTP2ReadFrameSize)

	header := http.Header{}
	dec := bhpack.NewDecoder(initialHeaderTableSize, nil)
	dec.SetEmitFunc(func(hf bhpack.HeaderField) {
		if hf.Value == "" || strings.HasPrefix(hf.Name, ":") || hf.Name == "<BAD INDEX>" {
			return
		}
		header.Set(hf.Name, hf.Value)
	})

	var body []byte
	for {
		f, err := framer.ReadFrame()
		if err != nil {
			break
		}

		switch ff := f.(type) {
		case *http2.HeadersFrame:
			decodeHTTP2HeaderBlock(dec, framer, ff)
		case *http2.DataFrame:
			// Data() strips padding and points into the framer's internal read
			// buffer.
			body = append(body, ff.Data()...)
			if ff.StreamEnded() {
				return body, header, len(body) > 0
			}
		}
	}

	return body, header, len(body) > 0
}

func decodeHTTP2HeaderBlock(dec *bhpack.Decoder, framer *http2.Framer, hf *http2.HeadersFrame) {
	frag := hf.HeaderBlockFragment()
	headersEnded := hf.HeadersEnded()
	for {
		if _, err := dec.Write(frag); err != nil {
			return
		}
		if headersEnded {
			return
		}
		nf, err := framer.ReadFrame()
		if err != nil {
			return
		}
		cf, ok := nf.(*http2.ContinuationFrame)
		if !ok {
			return
		}
		frag = cf.HeaderBlockFragment()
		headersEnded = cf.HeadersEnded()
	}
}
