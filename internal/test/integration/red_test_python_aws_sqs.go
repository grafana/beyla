// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
)

type (
	sqsQueueURL struct {
		QueueURL string `json:"QueueURL"`
	}
	sqsMessages struct {
		Messages []struct {
			MessageID     string `json:"MessageId"`
			ReceiptHandle string `json:"ReceiptHandle"`
			Body          string `json:"Body"`
		} `json:"Messages"`
	}
)

func testPythonAWSSQS(t *testing.T) {
	waitAWSProxy(t)
	waitForTestComponentsNoMetrics(t, localstackAddress)

	qr := sqsRequestWithData[sqsQueueURL](t, awsProxyAddress+"/createqueue")
	awsReq(t, awsProxyAddress+"/sendmessage?queue_url="+qr.QueueURL)
	mr := sqsRequestWithData[sqsMessages](t, awsProxyAddress+"/receivemessages?queue_url="+qr.QueueURL)
	require.Len(t, mr.Messages, 1)
	awsReq(t, awsProxyAddress+"/deletemessage?queue_url="+qr.QueueURL+"&receipt_handle="+mr.Messages[0].ReceiptHandle)
	awsReq(t, awsProxyAddress+"/getqueueattributes?queue_url="+qr.QueueURL)
	awsReq(t, awsProxyAddress+"/deletequeue?queue_url="+qr.QueueURL)

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		assertSQSOperation(t, "CreateQueue", qr.QueueURL, "", "")
		assertSQSOperation(t, "SendMessage", qr.QueueURL, mr.Messages[0].MessageID, "send")
		assertSQSOperation(t, "ReceiveMessage", qr.QueueURL, "", "receive")
		assertSQSOperation(t, "DeleteMessage", qr.QueueURL, "", "")
		assertSQSOperation(t, "GetQueueAttributes", qr.QueueURL, "", "")
		assertSQSOperation(t, "DeleteQueue", qr.QueueURL, "", "")
	}, test.Interval(time.Second))
}

func sqsRequestWithData[T sqsQueueURL | sqsMessages](t *testing.T, url string) T {
	t.Helper()

	resp, err := http.Get(url)
	require.NoError(t, err)
	require.True(t, resp.StatusCode >= 200 && resp.StatusCode <= 204)

	var data T
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&data))
	return data
}

func assertSQSOperation(t require.TestingT, op, expectedQueueURL, expectedMessageID, expectedOperationType string) {
	opName := "sqs." + op

	span := fetchAWSSpanByOP(t, opName)
	require.Equal(t, opName, span.OperationName)

	tag, found := jaeger.FindIn(span.Tags, "aws.request_id")
	require.True(t, found)
	require.NotEmpty(t, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "cloud.region")
	require.True(t, found)
	// localstack doesn't have a region, so we should match the default AWS one which is "us-east-1"
	require.Equal(t, "us-east-1", tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "aws.sqs.queue_url")
	require.True(t, found)
	require.Equal(t, expectedQueueURL, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "messaging.message.id")
	require.True(t, found)
	require.Equal(t, expectedMessageID, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "messaging.destination.name")
	require.True(t, found)
	require.Equal(t, "obi-queue", tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "messaging.operation.type")
	require.True(t, found)
	require.Equal(t, expectedOperationType, tag.Value)

	tag, found = jaeger.FindIn(span.Tags, "messaging.operation.name")
	require.True(t, found)
	require.Equal(t, op, tag.Value)
}
