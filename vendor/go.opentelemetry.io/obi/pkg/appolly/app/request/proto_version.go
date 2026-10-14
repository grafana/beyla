// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import "bytes"

// ProtoVersion is the wire protocol version, reported as network.protocol.version.
type ProtoVersion uint8

const (
	ProtoVersionUnknown ProtoVersion = iota
	ProtoVersionHTTP10
	ProtoVersionHTTP11
	ProtoVersionHTTP2
)

// String returns the semconv value, or "" when the version is unknown so
// callers omit the attribute.
func (v ProtoVersion) String() string {
	switch v {
	case ProtoVersionHTTP10:
		return "1.0"
	case ProtoVersionHTTP11:
		return "1.1"
	case ProtoVersionHTTP2:
		return "2"
	}

	return ""
}

// HTTPProtoVersion maps the major/minor pair parsed by net/http onto the enum.
func HTTPProtoVersion(major, minor int) ProtoVersion {
	switch {
	case major == 1 && minor == 0:
		return ProtoVersionHTTP10
	case major == 1 && minor == 1:
		return ProtoVersionHTTP11
	case major == 2:
		return ProtoVersionHTTP2
	}

	return ProtoVersionUnknown
}

// HTTPProtoVersionFromRequestLine reads the version from the third token of an
// HTTP/1 request line ("GET /path HTTP/1.1").
func HTTPProtoVersionFromRequestLine(req []byte) ProtoVersion {
	if end := bytes.IndexByte(req, 0); end >= 0 {
		req = req[:end]
	}
	if end := bytes.IndexAny(req, "\r\n"); end >= 0 {
		req = req[:end]
	}

	idx := bytes.LastIndex(req, []byte(" HTTP/"))
	if idx < 0 {
		return ProtoVersionUnknown
	}

	switch string(req[idx+len(" HTTP/"):]) {
	case "1.0":
		return ProtoVersionHTTP10
	case "1.1":
		return ProtoVersionHTTP11
	case "2", "2.0":
		return ProtoVersionHTTP2
	}

	return ProtoVersionUnknown
}
