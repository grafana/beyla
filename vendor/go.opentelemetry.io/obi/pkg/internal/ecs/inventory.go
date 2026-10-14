// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ecs // import "go.opentelemetry.io/obi/pkg/internal/ecs"

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	awsecs "github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

const describeTasksBatchSize = 100

type Client interface {
	ListTasks(context.Context, *awsecs.ListTasksInput, ...func(*awsecs.Options)) (*awsecs.ListTasksOutput, error)
	DescribeTasks(context.Context, *awsecs.DescribeTasksInput, ...func(*awsecs.Options)) (*awsecs.DescribeTasksOutput, error)
}

type Inventory struct {
	client  Client
	cluster string
	log     *slog.Logger

	mu                   sync.RWMutex
	serviceByIP          map[string]string
	serviceByContainerID map[string]string
	changes              chan struct{}
}

func NewInventory(client Client, cluster string) *Inventory {
	return &Inventory{
		client:      client,
		cluster:     cluster,
		log:         slog.With("component", "ecs.Inventory"),
		serviceByIP: map[string]string{},
		changes:     make(chan struct{}),
	}
}

func (i *Inventory) ServiceNameForIP(ip string) (string, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	name, ok := i.serviceByIP[ip]
	return name, ok
}

func (i *Inventory) ServiceNameForContainerID(id string) (string, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	name, ok := i.serviceByContainerID[id]
	return name, ok
}

// Changes is closed when a successful refresh publishes a new snapshot.
// Consumers obtain the next channel before reading the updated inventory.
func (i *Inventory) Changes() <-chan struct{} {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.changes
}

func (i *Inventory) Refresh(ctx context.Context) error {
	taskARNs, err := i.listTasks(ctx)
	if err != nil {
		return err
	}

	next := make(map[string]string, len(taskARNs))
	nextByContainerID := make(map[string]string, len(taskARNs))
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
				next[ip] = name
			}
			for _, container := range task.Containers {
				if container.RuntimeId != nil && *container.RuntimeId != "" {
					nextByContainerID[*container.RuntimeId] = name
				}
			}
		}
	}

	i.mu.Lock()
	i.serviceByIP = next
	i.serviceByContainerID = nextByContainerID
	close(i.changes)
	i.changes = make(chan struct{})
	i.mu.Unlock()
	return nil
}

func (i *Inventory) Run(ctx context.Context, refreshInterval time.Duration) {
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := i.Refresh(ctx); err != nil {
				i.log.Warn("can't refresh ECS task inventory", "error", err)
			}
		}
	}
}

func (i *Inventory) listTasks(ctx context.Context) ([]string, error) {
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
