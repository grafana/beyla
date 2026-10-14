// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"encoding/xml"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

var snsEndpoint = regexp.MustCompile(`^(?:sns(?:-fips)?|vpce-[a-z0-9-]+\.sns)\.([a-z0-9-]+)\.(?:vpce\.)?(?:amazonaws\.com(?:\.cn)?|api\.aws)$`)

type awsSNSResponse struct {
	Meta struct {
		RequestID string `xml:"RequestId"`
	} `xml:"ResponseMetadata"`
	RequestID string `xml:"RequestId"`
	Publish   struct {
		MessageID string `xml:"MessageId"`
	} `xml:"PublishResult"`
	CreateTopic struct {
		TopicARN string `xml:"TopicArn"`
	} `xml:"CreateTopicResult"`
	Batch struct {
		Failed []struct {
			Code string `xml:"Code"`
		} `xml:"Failed>member"`
	} `xml:"PublishBatchResult"`
	Error struct {
		Code string `xml:"Code"`
	} `xml:"Error"`
}

func AWSSNSSpan(baseSpan *request.Span, req *http.Request, resp *http.Response) (request.Span, bool) {
	params, ok := snsRequestParams(req)
	if !ok || !snsOperation(params.Get("Action")) {
		return *baseSpan, false
	}
	// Topic publishing is the supported destination type. SMS and mobile push
	// use different destination semantics.
	if params.Has("PhoneNumber") || params.Has("TargetArn") {
		return *baseSpan, false
	}

	responseBody, err := readAndRestoreBodyWithLimit(&resp.Body, maxCapturedPayloadBytes)
	var response awsSNSResponse
	if err != nil || xml.Unmarshal(responseBody, &response) != nil {
		// Request metadata remains useful when the response body is truncated.
		response = awsSNSResponse{}
	}

	host := extractHostname(req)
	endpoint := snsEndpoint.FindStringSubmatch(strings.ToLower(host))
	topicARN := params.Get("TopicArn")
	if topicARN == "" {
		topicARN = response.CreateTopic.TopicARN
	}
	topic := snsTopicARN(topicARN)
	if len(endpoint) == 0 && topic == nil {
		return *baseSpan, false
	}

	// SNS also returns request IDs in XML, including on Query API errors.
	meta, _ := parseAWSMeta(req, resp)
	if meta.RequestID == "" {
		meta.RequestID = response.Meta.RequestID
		if meta.RequestID == "" {
			meta.RequestID = response.RequestID
		}
	}
	meta.Region = parseAWSRegion(req)
	if len(endpoint) > 1 {
		meta.Region = endpoint[1]
	} else if topic != nil {
		meta.Region = topic[3]
	}
	sns := request.AWSSNS{Meta: meta, OperationName: params.Get("Action")}
	if topic != nil {
		sns.TopicARN = topicARN
		sns.Destination = topic[5]
	}
	switch sns.OperationName {
	case "Publish":
		sns.OperationType = request.MessagingSend
		sns.MessageID = response.Publish.MessageID
	case "PublishBatch":
		sns.OperationType = request.MessagingSend
		for key := range params {
			if strings.HasPrefix(key, "PublishBatchRequestEntries.member.") && strings.HasSuffix(key, ".Id") {
				sns.BatchCount++
			}
		}
		// A batch may contain failed entries even when HTTP reports success.
		if len(response.Batch.Failed) > 0 {
			sns.ErrorCode = response.Batch.Failed[0].Code
			if sns.ErrorCode == "" {
				sns.ErrorCode = "_OTHER"
			}
		}
	}
	if resp.StatusCode >= http.StatusBadRequest {
		sns.ErrorCode = response.Error.Code
		if sns.ErrorCode == "" {
			sns.ErrorCode = strconv.Itoa(resp.StatusCode)
		}
	}
	baseSpan.SubType = request.HTTPSubtypeAWSSNS
	baseSpan.AWS = &request.AWS{SNS: sns}
	return *baseSpan, true
}

func snsRequestParams(req *http.Request) (url.Values, bool) {
	switch req.Method {
	case http.MethodGet:
		params, err := url.ParseQuery(req.URL.RawQuery)
		return params, err == nil
	case http.MethodPost:
		mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/x-www-form-urlencoded" {
			return nil, false
		}
		body, readErr := readAndRestoreBodyWithLimit(&req.Body, maxCapturedPayloadBytes)
		params, parseErr := url.ParseQuery(string(body))
		return params, (readErr == nil && parseErr == nil) || errors.Is(readErr, io.ErrUnexpectedEOF)
	default:
		return nil, false
	}
}

// snsOperation reports whether op belongs to OBI's supported subset of SNS actions.
// AWS action reference: https://docs.aws.amazon.com/sns/latest/api/API_Operations.html
func snsOperation(op string) bool {
	switch op {
	case "Publish", "PublishBatch", "CreateTopic", "DeleteTopic", "ListTopics",
		"GetTopicAttributes", "SetTopicAttributes", "AddPermission", "RemovePermission",
		"Subscribe", "Unsubscribe",
		"ConfirmSubscription", "ListSubscriptions", "ListSubscriptionsByTopic",
		"GetSubscriptionAttributes", "SetSubscriptionAttributes":
		return true
	default:
		return false
	}
}

func snsTopicARN(arn string) []string {
	parts := strings.Split(arn, ":")
	if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] != "sns" ||
		!isAWSRegion(parts[3]) || parts[4] == "" || parts[5] == "" {
		return nil
	}
	return parts
}
