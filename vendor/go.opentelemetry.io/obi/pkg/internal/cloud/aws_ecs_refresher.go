// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cloud // import "go.opentelemetry.io/obi/pkg/internal/cloud"

import (
	"context"
	"fmt"
	"strings"

	awsecs "github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

const describeTasksBatchSize = 100

type ECSClient interface {
	ListTasks(context.Context, *awsecs.ListTasksInput, ...func(*awsecs.Options)) (*awsecs.ListTasksOutput, error)
	DescribeTasks(context.Context, *awsecs.DescribeTasksInput, ...func(*awsecs.Options)) (*awsecs.DescribeTasksOutput, error)
}

type ECSInventoryRefresher struct {
	client  ECSClient
	cluster string
}

func NewECSRefresher(client ECSClient, cluster string) *ECSInventoryRefresher {
	return &ECSInventoryRefresher{client: client, cluster: cluster}
}

func (i *ECSInventoryRefresher) Name() string { return "ecs" }

func (i *ECSInventoryRefresher) Refresh(ctx context.Context, snapshot *MetadataSnapshot) error {
	taskARNs, err := i.listTasks(ctx)
	if err != nil {
		return err
	}
	for start := 0; start < len(taskARNs); start += describeTasksBatchSize {
		end := min(start+describeTasksBatchSize, len(taskARNs))
		out, err := i.client.DescribeTasks(ctx, &awsecs.DescribeTasksInput{
			Cluster: &i.cluster,
			Tasks:   taskARNs[start:end],
		})
		if err != nil {
			return fmt.Errorf("describing ECS tasks: %w", err)
		}
		if len(out.Failures) > 0 {
			return fmt.Errorf("describing ECS tasks: %d task failures", len(out.Failures))
		}
		for _, task := range out.Tasks {
			name := serviceName(task.Group)
			if name == "" {
				continue
			}
			for _, ip := range taskIPs(task.Attachments) {
				snapshot.ServiceByIP[ip] = name
			}
			for _, container := range task.Containers {
				if container.RuntimeId != nil && *container.RuntimeId != "" {
					snapshot.ServiceByContainerID[*container.RuntimeId] = name
				}
			}
		}
	}
	return nil
}

func (i *ECSInventoryRefresher) listTasks(ctx context.Context) ([]string, error) {
	var taskARNs []string
	var nextToken *string
	for {
		out, err := i.client.ListTasks(ctx, &awsecs.ListTasksInput{
			Cluster:       &i.cluster,
			DesiredStatus: types.DesiredStatusRunning,
			NextToken:     nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("listing ECS tasks: %w", err)
		}
		taskARNs = append(taskARNs, out.TaskArns...)
		nextToken = out.NextToken
		if nextToken == nil || *nextToken == "" {
			return taskARNs, nil
		}
	}
}

func serviceName(group *string) string {
	if group == nil {
		return ""
	}
	name, ok := strings.CutPrefix(*group, "service:")
	if !ok {
		return ""
	}
	return name
}

func taskIPs(attachments []types.Attachment) []string {
	var ips []string
	for _, attachment := range attachments {
		for _, detail := range attachment.Details {
			if detail.Name != nil && *detail.Name == "privateIPv4Address" && detail.Value != nil {
				ips = append(ips, *detail.Value)
			}
		}
	}
	return ips
}
