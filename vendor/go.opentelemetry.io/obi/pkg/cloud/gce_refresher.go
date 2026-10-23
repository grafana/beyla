// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cloud // import "go.opentelemetry.io/obi/pkg/cloud"

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"path"
	"strconv"
	"time"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
)

const (
	instanceStatusRunning    = "RUNNING"
	defaultGCERefreshTimeout = 30 * time.Second
)

// GCEInventoryRefresher maps VM addresses and IDs to their managed instance group names.
type GCEInventoryRefresher struct {
	client         *compute.Service
	project        string
	zone           string
	refreshTimeout time.Duration
}

func NewGCERefresher(client *compute.Service, project, zone string) *GCEInventoryRefresher {
	return &GCEInventoryRefresher{
		client:         client,
		project:        project,
		zone:           zone,
		refreshTimeout: defaultGCERefreshTimeout,
	}
}

func (i *GCEInventoryRefresher) Name() string { return "gce" }

func (i *GCEInventoryRefresher) Refresh(ctx context.Context, snapshot *MetadataSnapshot) error {
	// One deadline covers group enumeration and all instance lookups.
	ctx, cancel := context.WithTimeout(ctx, i.refreshTimeout)
	defer cancel()

	groups, err := i.listGroups(ctx)
	if err != nil {
		return err
	}
	nextByIP := map[string]string{}
	nextByInstanceID := map[string]string{}
	instanceByIP := map[string]string{}
	ambiguousIPs := map[string]struct{}{}

	for _, group := range groups {
		instances, err := i.runningInstances(ctx, group)
		if err != nil {
			var apiErr *googleapi.Error
			if errors.As(err, &apiErr) && apiErr.Code == http.StatusNotFound {
				// A group can disappear after enumeration.
				continue
			}
			return err
		}
		for _, instance := range instances {
			if instance.Id == 0 {
				return fmt.Errorf("instance %q has no ID", instance.Name)
			}
			id := strconv.FormatUint(instance.Id, 10)
			if previous, ok := nextByInstanceID[id]; ok && previous != group {
				return fmt.Errorf("instance %q belongs to both %q and %q", instance.Name, previous, group)
			}
			nextByInstanceID[id] = group
			for _, nic := range instance.NetworkInterfaces {
				if nic == nil || nic.NetworkIP == "" {
					continue
				}
				ip := nic.NetworkIP
				if previous, ok := instanceByIP[ip]; ok && previous != id {
					// Private addresses can overlap across VPC networks.
					ambiguousIPs[ip] = struct{}{}
				}
				instanceByIP[ip] = id
				nextByIP[ip] = group
			}
		}
	}
	for ip := range ambiguousIPs {
		delete(nextByIP, ip)
	}

	maps.Copy(snapshot.ServiceByIP, nextByIP)
	maps.Copy(snapshot.ServiceByInstanceID, nextByInstanceID)
	return nil
}

func (i *GCEInventoryRefresher) listGroups(ctx context.Context) ([]string, error) {
	var groups []string
	err := i.client.InstanceGroupManagers.List(i.project, i.zone).Pages(ctx, func(page *compute.InstanceGroupManagerList) error {
		for _, group := range page.Items {
			if group == nil || group.Name == "" {
				return errors.New("managed instance group has no name")
			}
			groups = append(groups, group.Name)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing managed instance groups: %w", err)
	}
	return groups, nil
}

func (i *GCEInventoryRefresher) runningInstances(ctx context.Context, group string) ([]*compute.Instance, error) {
	var instances []*compute.Instance
	call := i.client.InstanceGroupManagers.ListManagedInstances(i.project, i.zone, group)
	err := call.Pages(ctx, func(page *compute.InstanceGroupManagersListManagedInstancesResponse) error {
		for _, member := range page.ManagedInstances {
			if member == nil || member.Instance == "" {
				return errors.New("group member has no instance reference")
			}
			name := path.Base(member.Instance)
			instance, err := i.client.Instances.Get(i.project, i.zone, name).Context(ctx).Do()
			if err != nil {
				var apiErr *googleapi.Error
				if errors.As(err, &apiErr) && apiErr.Code == http.StatusNotFound {
					// A VM can disappear between membership and instance lookups.
					continue
				}
				return fmt.Errorf("getting instance %q: %w", name, err)
			}
			if instance.Status == instanceStatusRunning {
				instances = append(instances, instance)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reading managed instance group %q: %w", group, err)
	}
	return instances, nil
}
