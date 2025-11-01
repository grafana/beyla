// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
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
	s3.Bucket, s3.Key = parseS3bucketKey(req.URL.Path)
	s3.Method = inferS3Method(req)
	if s3.Method == "" {
		return s3, errors.New("unable to parse s3 operation")
	}

	return s3, nil
}

func parseS3bucketKey(path string) (string, string) {
	// S3 paths are generally in the format 'PUT /bucket/key'
	var bucket, key string
	parts := bytes.SplitN([]byte(path), []byte("/"), 3)
	if len(parts) >= 2 {
		bucket = string(parts[1])
	}
	if len(parts) == 3 {
		key = string(parts[2])
	}
	return bucket, key
}

// This is a naive inference of S3 operations based on HTTP method and URL path/query
func inferS3Method(req *http.Request) string {
	q := req.URL.Query()
	path := strings.Trim(strings.TrimPrefix(req.URL.Path, "/"), "/")
	parts := strings.Split(path, "/")

	switch req.Method {
	case http.MethodGet:
		switch {
		case path == "":
			return "ListBuckets"
		case len(parts) == 1:
			return "ListObjects"
		case q.Has("uploads"):
			return "ListMultipartUploads"
		case q.Has("uploadId"):
			return "ListParts"
		default:
			return "GetObject"
		}
	case http.MethodPut:
		if q.Has("uploadId") && q.Has("partNumber") {
			return "UploadPart"
		}
		if q.Has("uploadId") {
			return "CompleteMultipartUpload"
		}

		switch len(parts) {
		case 1:
			// PUT /my-bucket -> Create bucket
			return "CreateBucket"
		default:
			// PUT /my-bucket/object.txt
			return "PutObject"
		}
	case http.MethodPost:
		if q.Has("uploads") {
			return "CreateMultipartUpload"
		}
		if q.Has("uploadId") {
			return "CompleteMultipartUpload"
		}
		return "PutObject"
	case http.MethodDelete:
		if q.Has("uploadId") {
			return "AbortMultipartUpload"
		}
		if len(parts) == 1 {
			return "DeleteBucket"
		}
		return "DeleteObject"
	}

	return ""
}
