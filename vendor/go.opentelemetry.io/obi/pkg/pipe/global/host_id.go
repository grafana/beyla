// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package global

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.opentelemetry.io/contrib/detectors/aws/ec2/v2"
	"go.opentelemetry.io/contrib/detectors/azure/azurevm"
	"go.opentelemetry.io/contrib/detectors/gcp"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
)

type hostIDFetcher func(context.Context, time.Duration) (string, error)

type fetcher struct {
	name  string
	fetch hostIDFetcher
}

func cilog() *slog.Logger {
	return slog.With("component", "ContextInfo")
}

// FetchHostID tries to get the host ID from one of the following sources, by priority
// 1. If Beyla runs in AWS, GCP or Azure, it will take the instance ID
// 2. Otherwise, will try to read the Kubernetes Node MachineID field
// 3. Otherwise, will try to read the machine ID from the local OS filesystem
// 4. Otherwise, will fallback to the Hostname
// This process is known to fail when Beyla runs inside a Kubernetes Pod out of the cloud providers
// mentioned in (1). In that case, the host.id will be later set to the full hostname.
// This method must be invoked once the ContextInfo object is completely initialized
func (ci *ContextInfo) FetchHostID(ctx context.Context, timeout time.Duration) {
	log := cilog().With("func", "fetchHostID")
	fetchers := []fetcher{
		{name: "AWS", fetch: ec2HostIDFetcher},
		{name: "Azure", fetch: azureHostIDFetcher},
		{name: "GCP", fetch: gcpHostIDFetcher},
		{name: "KubeNode", fetch: ci.kubeNodeFetcher},
		{name: "local", fetch: linuxLocalMachineIDFetcher},
	}
	// if all the methods fail, keep at least the fallback method error
	var err error
	for _, f := range fetchers {
		log := log.With("fetcher", f.name)
		log.Debug("trying to fetch host ID")
		var id string
		if id, err = f.fetch(ctx, timeout); err == nil {
			log.Info("got host ID", "hostID", id)
			ci.HostID = id
			return
		}
		log.Debug("didn't get host ID", "cause", err)
	}
	log.Debug("falling back to local host ID. This might be inaccurate in containerized systems")
	ci.HostID, err = os.Hostname()
	if err != nil {
		log.Warn("getting host ID from host name", "error", err)
	}
}

func azureHostIDFetcher(ctx context.Context, timeout time.Duration) (string, error) {
	return detectHostID(ctx, timeout, azurevm.New())
}

func gcpHostIDFetcher(ctx context.Context, timeout time.Duration) (string, error) {
	return detectHostID(ctx, timeout, gcp.NewDetector())
}

func ec2HostIDFetcher(ctx context.Context, timeout time.Duration) (string, error) {
	return detectHostID(ctx, timeout, ec2.NewResourceDetector())
}

func detectHostID(ctx context.Context, timeout time.Duration, detector resource.Detector) (string, error) {
	// passing a cancellable context to the detector.Detect(ctx) does not always
	// end the connection prematurely, so we wrap its invocation into a goroutine
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resCh := make(chan *resource.Resource, 1)
	errCh := make(chan error, 1)
	go func() {
		if res, err := detector.Detect(ctx); err != nil {
			errCh <- err
		} else {
			resCh <- res
		}
	}()
	var res *resource.Resource
	select {
	case res = <-resCh: // continue!
	case err := <-errCh:
		return "", err
	case <-cctx.Done():
		return "", errors.New("timed out waiting for host ID connection")
	}
	for _, attr := range res.Attributes() {
		if attr.Key == semconv.HostIDKey {
			return attr.Value.Emit(), nil
		}
	}
	return "", fmt.Errorf("can't find host.id in %v", res.Attributes())
}

func (ci *ContextInfo) kubeNodeFetcher(ctx context.Context, _ time.Duration) (string, error) {
	if ci.K8sInformer == nil || !ci.K8sInformer.IsKubeEnabled() {
		return "", errors.New("kubernetes is not enabled")
	}
	nodeName, err := ci.K8sInformer.CurrentNodeName(ctx)
	if err != nil {
		return "", fmt.Errorf("can't get node name: %w", err)
	}
	kubeClient, err := ci.K8sInformer.KubeClient()
	if err != nil {
		return "", fmt.Errorf("can't get kubernetes client: %w", err)
	}
	nodes, err := kubeClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{
		FieldSelector: "metadata.name=" + nodeName,
	})
	if err != nil || len(nodes.Items) == 0 {
		return "", fmt.Errorf("can't get node %s: %w", nodeName, err)
	}
	return nodes.Items[0].Status.NodeInfo.MachineID, nil
}

func linuxLocalMachineIDFetcher(_ context.Context, _ time.Duration) (string, error) {
	if result, err := os.ReadFile("/etc/machine-id"); err == nil && len(bytes.TrimSpace(result)) > 0 {
		return string(bytes.TrimSpace(result)), nil
	}

	if result, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil && len(bytes.TrimSpace(result)) > 0 {
		return string(bytes.TrimSpace(result)), nil
	} else {
		return "", fmt.Errorf("can't read host ID: %w", err)
	}
}
