// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"errors"
	"net/http"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func AWSS3Span(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	s3, err := parseAWSS3(req, resp)
	if err != nil {
		return *baseSpan, false
	}

	// https://opentelemetry.io/docs/specs/semconv/object-stores/s3/
	baseSpan.SubType = request.HTTPSubtypeAWSS3
	baseSpan.AWS = &request.AWS{
		S3: s3,
	}

	return *baseSpan, true
}

func parseAWSS3(req *http.Request, resp *http.Response) (request.AWSS3, error) {
	s3 := request.AWSS3{}

	var err error
	s3.Meta, err = parseAWSMeta(req, resp)
	if err != nil {
		return s3, err
	}
	if s3.Meta.ExtendedRequestID == "" {
		return s3, errors.New("missing x-amz-id-2 header")
	}
	s3.Bucket, s3.Key = parseS3bucketKey(req)
	s3.Method = inferS3Method(req)
	if s3.Method == "" {
		return s3, errors.New("unable to parse s3 operation")
	}

	return s3, nil
}

// parseS3bucketKey extracts the S3 bucket name and object key from an HTTP request.
// It supports both virtual-hosted-style (bucket.s3.region.amazonaws.com)
// and path-style (s3.amazonaws.com/bucket/object) addressing.
//
// Examples:
//
//	Host: my-bucket.s3.eu-west-1.amazonaws.com, Path: /foo/bar.txt
//	  => ("my-bucket", "foo/bar.txt")
//
//	Host: s3.amazonaws.com, Path: /my-bucket/foo/bar.txt
//	  => ("my-bucket", "foo/bar.txt")
//
//	Host: my-bucket.s3.amazonaws.com, Path: /
//	  => ("my-bucket", "")
func parseS3bucketKey(req *http.Request) (string, string) {
	path := strings.TrimPrefix(req.URL.Path, "/")

	// Case 1: Virtual-hosted–style — bucket in the hostname.
	// Example: my-bucket.s3.amazonaws.com /foo/bar.txt
	if strings.Contains(req.Host, ".s3.") {
		bucket := strings.SplitN(req.Host, ".s3.", 2)[0]
		return bucket, path
	}

	// Case 2: Path-style — bucket in the first path segment.
	// Example: s3.amazonaws.com /my-bucket/foo/bar.txt
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "", ""
	}

	bucket := parts[0]
	key := ""
	if len(parts) > 1 {
		key = parts[1]
	}
	return bucket, key
}

// This is a naive inference of S3 operations based on HTTP method and URL path/query
func inferS3Method(req *http.Request) string {
	path := strings.TrimPrefix(req.URL.Path, "/")

	var bucket, object string
	// --- Virtual-hosted–style URL ---
	// Example: PUT bucket.s3.eu-west-1.amazonaws.com /hello.txt
	if strings.Contains(req.Host, ".s3.") {
		bucket = strings.SplitN(req.Host, ".s3.", 2)[0]
		object = path // path may be empty or "object-key"
	} else {
		// --- Path-style URL ---
		// Example: PUT s3.amazonaws.com /bucket/hello.txt
		parts := strings.SplitN(path, "/", 2)
		if len(parts) > 0 {
			bucket = parts[0]
		}
		if len(parts) > 1 {
			object = parts[1]
		}
	}

	hasBucket := bucket != ""
	hasObject := object != ""

	switch req.Method {
	case http.MethodPut:
		if hasBucket && !hasObject {
			return "CreateBucket"
		}
		if hasBucket && hasObject {
			return "PutObject"
		}
	case http.MethodDelete:
		if hasBucket && !hasObject {
			return "DeleteBucket"
		}
		if hasBucket && hasObject {
			return "DeleteObject"
		}
	case http.MethodGet:
		if !hasBucket {
			return "ListBuckets"
		}
		if hasBucket && !hasObject {
			return "ListObjects"
		}
		return "GetObject"
	}

	return ""
}
