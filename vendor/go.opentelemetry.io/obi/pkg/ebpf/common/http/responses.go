// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// getResponseBody tries to read the body as plain text and then
// if it's encoded in compressed format, it tries to decompress
func getResponseBody(resp *http.Response) ([]byte, error) {
	respB, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(respB))

	// http.ReadResponse does NOT auto-decompress Content-Encoding
	// (only http.Transport does, and only for gzip). Decompress manually.
	body := respB
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && len(respB) > 0 {
		dec, err := decompressBody(enc, respB)
		if err != nil {
			return nil, fmt.Errorf("decompress error (enc=%s, truncated body?): %w", enc, err)
		}
		body = dec
	}

	return body, nil
}

// decompressBody decompresses b according to the Content-Encoding value.
// Mirrors what http.Transport does for gzip, extended to cover zstd, deflate and brotli.
func decompressBody(encoding string, b []byte) ([]byte, error) {
	switch encoding {
	case "gzip":
		gr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		return io.ReadAll(gr)
	case "zstd":
		zr, err := zstd.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		return io.ReadAll(zr)
	case "deflate":
		fr := flate.NewReader(bytes.NewReader(b))
		defer fr.Close()
		return io.ReadAll(fr)
	case "br":
		return io.ReadAll(brotli.NewReader(bytes.NewReader(b)))
	default:
		return b, nil
	}
}
