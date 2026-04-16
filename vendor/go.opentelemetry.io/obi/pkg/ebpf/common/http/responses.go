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

	"go.opentelemetry.io/obi/pkg/config"
)

// Keep the decompressed response cap aligned with the maximum captured payload size
// so body enrichment cannot expand a compressed payload beyond the configured
// userspace budget.
const maxDecompressedResponseBodyBytes = config.MaxCapturedPayloadBytes

var errResponseBodyTooLarge = fmt.Errorf(
	"response body exceeds decompression limit of %d bytes",
	maxDecompressedResponseBodyBytes,
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
// Mirrors what http.Transport does for gzip, extended to cover zstd, deflate
// and brotli. Unsupported encodings are returned unchanged. Decompressed
// output is capped at maxDecompressedResponseBodyBytes, and it returns
// errResponseBodyTooLarge if that limit is exceeded.
func decompressBody(encoding string, b []byte) ([]byte, error) {
	var (
		reader  io.Reader
		closeFn func()
		err     error
	)

	switch encoding {
	case "gzip":
		var gr *gzip.Reader
		gr, err = gzip.NewReader(bytes.NewReader(b))
		reader = gr
		closeFn = func() { _ = gr.Close() }
	case "zstd":
		var zr *zstd.Decoder
		zr, err = zstd.NewReader(bytes.NewReader(b))
		reader = zr
		closeFn = zr.Close
	case "deflate":
		fr := flate.NewReader(bytes.NewReader(b))
		reader = fr
		closeFn = func() { _ = fr.Close() }
	case "br":
		reader = brotli.NewReader(bytes.NewReader(b))
	default:
		return b, nil
	}

	if err != nil {
		return nil, err
	}
	if closeFn != nil {
		defer closeFn()
	}

	return readBodyWithLimit(reader, maxDecompressedResponseBodyBytes)
}

func readBodyWithLimit(reader io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}

	if int64(len(body)) > limit {
		return nil, errResponseBodyTooLarge
	}

	return body, nil
}
