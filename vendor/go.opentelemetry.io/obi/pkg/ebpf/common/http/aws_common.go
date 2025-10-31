// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"errors"
	"net/http"
	"regexp"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

var (
	requestIDHeader         = "x-amz-requestid"
	requestIDHeader2        = "x-amz-request-id"
	requestIDHeader3        = "x-amzn-requestid"
	requestIDHeader4        = "x-amzn-request-id"
	extendedRequestIDHeader = "x-amz-id-2"
)

var awsRegionRgx = regexp.MustCompile(`(?:^|\.)([a-z]{2}-[a-z]+-\d)\.amazonaws\.com$`)

func parseAWSMeta(req *http.Request, resp *http.Response) (request.AWSMeta, error) {
	meta := request.AWSMeta{}

	for k, v := range resp.Header {
		lk := strings.ToLower(k)
		if lk == requestIDHeader || lk == requestIDHeader2 || lk == requestIDHeader3 || lk == requestIDHeader4 {
			if len(v) > 0 {
				meta.RequestID = v[0]
			}
		}
		if lk == extendedRequestIDHeader {
			if len(v) > 0 {
				meta.ExtendedRequestID = v[0]
			}
		}
	}
	if meta.RequestID == "" {
		return meta, errors.New("missing x-amz-request-id header")
	}

	meta.Region = parseAWSRegion(req)

	return meta, nil
}

func parseAWSRegion(req *http.Request) string {
	match := awsRegionRgx.FindStringSubmatch(req.URL.Host)
	if len(match) >= 2 {
		return match[1]
	}
	return ""
}
