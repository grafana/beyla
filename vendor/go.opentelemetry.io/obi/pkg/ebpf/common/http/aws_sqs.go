// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const (
	amzTargetHeader = "x-amz-target"
)

type awsSQSBody struct {
	QueueURL  string `json:"QueueUrl"`
	MessageID string `json:"MessageId"`
}

func AWSSQSSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	sqs, err := parseAWSSQS(req, resp)
	if err != nil {
		return *baseSpan, false
	}

	// https://opentelemetry.io/docs/specs/semconv/messaging/sqs/
	baseSpan.SubType = request.HTTPSubtypeAWSSQS
	baseSpan.AWS = &request.AWS{
		SQS: sqs,
	}

	return *baseSpan, true
}

func parseAWSSQS(req *http.Request, resp *http.Response) (request.AWSSQS, error) {
	sqs := request.AWSSQS{}

	reqB, err := io.ReadAll(req.Body)
	if err != nil {
		return sqs, fmt.Errorf("read SQS request body: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewBuffer(reqB))

	respB, err := io.ReadAll(resp.Body)
	if err != nil {
		return sqs, fmt.Errorf("read SQS response body: %w", err)
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(respB))

	sqs.Meta, err = parseAWSMeta(req, resp)
	if err != nil {
		return sqs, err
	}

	sqs.OperationName = parseSQSOperation(req)
	if sqs.OperationName == "" {
		return sqs, errors.New("missing SQS operation")
	}
	sqs.OperationType = inferSQSOperationType(sqs.OperationName)
	sqs.MessageID = parseSQSMessageID(reqB, respB)
	sqs.QueueURL = parseSQSQueueURL(reqB, respB)
	sqs.Destination = parseSQSDestination(sqs.QueueURL)

	return sqs, nil
}

func parseSQSOperation(req *http.Request) string {
	op := req.Header.Get(amzTargetHeader)
	if op == "" {
		return ""
	}

	parts := strings.SplitN(op, ".", 2)
	if len(parts) != 2 {
		return ""
	}

	return parts[1]
}

func parseSQSQueueURL(reqB, respB []byte) string {
	var b awsSQSBody
	if err := json.Unmarshal(reqB, &b); err == nil && b.QueueURL != "" {
		return b.QueueURL
	}
	if err := json.Unmarshal(respB, &b); err == nil && b.QueueURL != "" {
		return b.QueueURL
	}
	return ""
}

func parseSQSMessageID(reqB, respB []byte) string {
	var b awsSQSBody
	if err := json.Unmarshal(reqB, &b); err == nil && b.MessageID != "" {
		return b.MessageID
	}
	if err := json.Unmarshal(respB, &b); err == nil && b.MessageID != "" {
		return b.MessageID
	}
	return ""
}

func parseSQSDestination(queueURL string) string {
	parts := strings.Split(queueURL, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func inferSQSOperationType(opName string) string {
	switch opName {
	case "SendMessage", "SendMessageBatch":
		return "send"
	case "ReceiveMessage":
		return "receive"
	default:
		return ""
	}
}
