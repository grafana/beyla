package global

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"go.opentelemetry.io/contrib/detectors/aws/ec2"
	"go.opentelemetry.io/contrib/detectors/azure/azurevm"
	"go.opentelemetry.io/contrib/detectors/gcp"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type hostIDFetcher func(context.Context) (string, error)

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
func (ci *ContextInfo) FetchHostID(ctx context.Context) {
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
		if id, err = f.fetch(ctx); err == nil {
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

func azureHostIDFetcher(ctx context.Context) (string, error) {
	return detectHostID(ctx, azurevm.New())
}

func gcpHostIDFetcher(ctx context.Context) (string, error) {
	return detectHostID(ctx, gcp.NewDetector())
}

func ec2HostIDFetcher(ctx context.Context) (string, error) {
	return detectHostID(ctx, ec2.NewResourceDetector())
}

func detectHostID(ctx context.Context, detector resource.Detector) (string, error) {
	res, err := detector.Detect(ctx)
	if err != nil {
		return "", err
	}
	for _, attr := range res.Attributes() {
		if attr.Key == semconv.HostIDKey {
			return attr.Value.Emit(), nil
		}
	}
	return "", fmt.Errorf("can't find host.id in %v", res.Attributes())
}

func (ci *ContextInfo) kubeNodeFetcher(ctx context.Context) (string, error) {
	if !ci.K8sInformer.IsKubeEnabled() {
		return "", errors.New("kubernetes is not enabled")
	}
	log := cilog().With("func", "kubeNodeFetcher")
	kubeClient, err := ci.K8sInformer.KubeClient()
	if err != nil {
		return "", fmt.Errorf("can't get kubernetes client: %w", err)
	}
	// fist: get the current pod name and namespace
	currentPod, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("can't get hostname of current pod: %w", err)
	}
	var currentNamespace string
	if nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err != nil {
		log.Warn("can't read service account namespace. Two Beyla pods with the same"+
			" name could result in inaccuracies in the host.id attribute", "error", err)
	} else {
		currentNamespace = string(nsBytes)
	}
	// second: get the node for the current Pod
	// using List instead of Get because to not require extra serviceaccount permissions
	pods, err := kubeClient.CoreV1().Pods(currentNamespace).List(ctx, v1.ListOptions{
		FieldSelector: "metadata.name=" + currentPod,
	})
	if err != nil || len(pods.Items) == 0 {
		return "", fmt.Errorf("can't get pod %s/%s: %w", currentNamespace, currentPod, err)
	}
	pod := pods.Items[0]
	// third: get the node MachineID from NodeInfo
	// using List instead of Get because to not require extra serviceaccount permissions
	nodes, err := kubeClient.CoreV1().Nodes().List(ctx, v1.ListOptions{
		FieldSelector: "metadata.name=" + pod.Spec.NodeName,
	})
	if err != nil || len(nodes.Items) == 0 {
		return "", fmt.Errorf("can't get node %s: %w", pod.Spec.NodeName, err)
	}
	return nodes.Items[0].Status.NodeInfo.MachineID, nil
}

func linuxLocalMachineIDFetcher(_ context.Context) (string, error) {
	if result, err := os.ReadFile("/etc/machine-id"); err == nil || len(result) == 0 {
		return string(bytes.TrimSpace(result)), nil
	}

	if result, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil || len(result) == 0 {
		return string(bytes.TrimSpace(result)), nil
	} else {
		return "", fmt.Errorf("can't read host ID: %w", err)
	}
}
