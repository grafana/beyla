// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// Keep the decompressed response cap aligned with the maximum captured payload size
// so body enrichment cannot expand a compressed payload beyond the configured
// userspace budget.
const (
	maxCapturedPayloadBytes          = 1 << 18
	maxDecompressedResponseBodyBytes = maxCapturedPayloadBytes
)

var errResponseBodyTooLarge = fmt.Errorf(
	"response body exceeds decompression limit of %d bytes",
	maxDecompressedResponseBodyBytes,
)

// requestPath extracts the request path from multiple URL representations,
// handling opaque URLs and fallback to RequestURI. This is a shared helper
// used by various protocol detectors (Qwen, rerank, etc.) to avoid code duplication.
func requestPath(req *http.Request) string {
	if req == nil {
		return ""
	}
	if req.URL != nil {
		if req.URL.Path != "" {
			return req.URL.Path
		}
		if req.URL.Opaque != "" {
			if parsed, err := url.Parse(req.URL.Opaque); err == nil && parsed.Path != "" {
				return parsed.Path
			}
			if strings.HasPrefix(req.URL.Opaque, "/") {
				return req.URL.Opaque
			}
		}
	}
	if req.RequestURI == "" {
		return ""
	}
	if parsed, err := url.ParseRequestURI(req.RequestURI); err == nil && parsed.Path != "" {
		return parsed.Path
	}
	return req.RequestURI
}

// getResponseBody tries to read the body as plain text and then
// if it's encoded in compressed format, it tries to decompress
func getResponseBody(resp *http.Response) ([]byte, error) {
	respB, readErr := io.ReadAll(resp.Body)
	if readErr != nil && len(respB) == 0 {
		return nil, readErr
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(respB))

	// http.ReadResponse does NOT auto-decompress Content-Encoding
	// (only http.Transport does, and only for gzip). Decompress manually.
	body := respB
	var decErr error
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && len(respB) > 0 {
		dec, err := decompressBody(enc, respB)
		if err != nil && len(dec) == 0 {
			return nil, fmt.Errorf("decompress error (enc=%s, truncated body?): %w", enc, err)
		}
		body = dec
		decErr = err
	}

	if decErr != nil {
		return body, decErr
	}
	return body, readErr
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
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}

	if int64(len(body)) > limit {
		return nil, errResponseBodyTooLarge
	}

	return body, err
}
