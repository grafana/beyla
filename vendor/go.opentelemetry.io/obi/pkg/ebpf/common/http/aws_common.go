// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

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

var (
	awsRegionURLRgx  = regexp.MustCompile(`(?:^|\.)([a-z0-9-]+)\.amazonaws\.com(\.[a-z]+)?$`)
	awsRegionURLRgx2 = regexp.MustCompile(`([a-z0-9-]+)-([a-z0-9-]+)\.amazonaws\.com(\.[a-z]+)?$`)
	awsRegionRgx     = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-\d+$`)
	awsRegionRgx2    = regexp.MustCompile(`^cn-[a-z]+-\d+$`)
)

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

// parseAWSRegion extracts the AWS region from the Host in a request.
// It supports both virtual-hosted–style and path-style endpoints.
// If no explicit region is found, the default region ("us-east-1") is returned.
//
// Examples:
//
//	Host: bucket.s3.eu-west-1.amazonaws.com => "eu-west-1"
//	Host: bucket.s3.amazonaws.com           => "us-east-1"
//	Host: ec2.us-west-2.amazonaws.com       => "us-west-2"
//	Host: s3.eu-central-1.amazonaws.com     => "eu-central-1"
//	Host: sns.cn-north-1.amazonaws.com.cn   => "cn-north-1"
//	Host: sts.amazonaws.com                 => "us-east-1" (default)
func parseAWSRegion(req *http.Request) string {
	// Common AWS endpoint patterns:
	//   <service>.<region>.amazonaws.com
	//   <service>.<region>.amazonaws.com.cn
	//   <service>.amazonaws.com
	//
	// Examples captured by this regex:
	//   ec2.us-east-2.amazonaws.com            => us-east-2
	//   monitoring.us-gov-west-1.amazonaws.com => us-gov-west-1
	//   s3.cn-north-1.amazonaws.com.cn         => cn-north-1
	if m := awsRegionURLRgx.FindStringSubmatch(req.Host); len(m) >= 2 {
		if isAWSRegion(m[1]) {
			return m[1]
		}
	}

	// Fallback pattern for "service.s3.region.amazonaws.com" style:
	//   bucket.s3.eu-west-1.amazonaws.com => eu-west-1
	if m := awsRegionURLRgx2.FindStringSubmatch(req.Host); len(m) >= 2 {
		if isAWSRegion(m[1]) {
			return m[1]
		}
	}

	// Default AWS region when none is found
	return "us-east-1"
}

func isAWSRegion(region string) bool {
	return awsRegionRgx.MatchString(region) || awsRegionRgx2.MatchString(region)
}
