// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const (
	requestIDHeader         = "x-amz-request-id"
	requestIDHeader2        = "x-amz-requestid"
	extendedRequestIDHeader = "x-amz-id-2"
)

var awsRegionRgx = regexp.MustCompile(`(?:^|\.)([a-z]{2}-[a-z]+-\d)\.amazonaws\.com$`)

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

	reqB, err := io.ReadAll(req.Body)
	if err != nil {
		return s3, fmt.Errorf("read S3 request body: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewBuffer(reqB))

	respB, err := io.ReadAll(resp.Body)
	if err != nil {
		return s3, fmt.Errorf("read S3 response body: %w", err)
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(respB))

	for k, v := range resp.Header {
		lk := strings.ToLower(k)
		if lk == requestIDHeader || lk == requestIDHeader2 {
			s3.RequestID = v[0]
		}
		if lk == extendedRequestIDHeader {
			s3.ExtendedRequestID = v[0]
		}
	}
	if s3.RequestID == "" {
		return s3, errors.New("missing x-amz-request-id header")
	}

	s3.Bucket, s3.Key = parseS3bucketKey(req.URL.Path)
	s3.Region = parseAWSRegion(req)
	s3.Method = inferS3Method(req)

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

func parseAWSRegion(req *http.Request) string {
	match := awsRegionRgx.FindStringSubmatch(req.URL.Host)
	if len(match) >= 2 {
		return match[1]
	}
	return ""
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
