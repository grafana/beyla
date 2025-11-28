// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
)

const (
	s3BucketName = "obi-bucket"
	s3ObjectKey  = "hello.txt"
	// Extended request ID is hardcoded for all localstack S3 requests
	s3ExtendedRequestID = "s9lzHYrFp76ZVxRcpX9+5cjAnEH2ROuNkd2BHfIa6UkFVdtjf5mKR3/eTPFvsiP/XV/VLi31234="
)

func testPythonAWSS3(t *testing.T) {
	waitAWSProxy(t)
	waitForTestComponentsNoMetrics(t, localstackAddress)

	awsReq(t, awsProxyAddress+"/createbucket")
	awsReq(t, awsProxyAddress+"/createobject")
	awsReq(t, awsProxyAddress+"/listobjects")
	awsReq(t, awsProxyAddress+"/deleteobject")
	awsReq(t, awsProxyAddress+"/deletebucket")

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		assertS3Operation(t, "CreateBucket", "")
		assertS3Operation(t, "PutObject", s3ObjectKey)
		assertS3Operation(t, "ListObjects", "")
		assertS3Operation(t, "DeleteObject", s3ObjectKey)
		assertS3Operation(t, "DeleteBucket", "")
	}, test.Interval(time.Second))
}

func assertS3Operation(t require.TestingT, op, expectedKey string) {
	opName := "s3." + op

	span := fetchAWSSpanByOP(t, opName)
	require.Equal(t, opName, span.OperationName)

	tag, found := jaeger.FindIn(span.Tags, "rpc.method")
	require.True(t, found)
	require.Equal(t, op, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "aws.s3.key")
	require.True(t, found)
	require.Equal(t, expectedKey, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "rpc.service")
	require.True(t, found)
	require.Equal(t, "S3", tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "rpc.system")
	require.True(t, found)
	require.Equal(t, "aws-api", tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "aws.s3.bucket")
	require.True(t, found)
	require.Equal(t, s3BucketName, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "aws.request_id")
	require.True(t, found)
	require.NotEmpty(t, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "aws.extended_request_id")
	require.True(t, found)
	require.Equal(t, s3ExtendedRequestID, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "cloud.region")
	require.True(t, found)
	// localstack doesn't have a region, so we should match the default AWS one which is "us-east-1"
	require.Equal(t, "us-east-1", tag.Value)
}
