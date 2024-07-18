package global

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/prometheus/prometheus/discovery/kubernetes"
	"go.opentelemetry.io/contrib/detectors/aws/ec2"
	"go.opentelemetry.io/contrib/detectors/azure/azurevm"
	"go.opentelemetry.io/contrib/detectors/gcp"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
)

type hostIDFetcher func(context.Context) (string, error)

type fetcher struct {
	name  string
	fetch hostIDFetcher
}

// FetchHostID tries to get the host ID from one of the following sources, by priority
// 1. If Beyla runs in AWS, GCP or Azure, it will take the instance ID
// 2. Otherwise, will try to read the machine ID
// This process is known to fail when Beyla runs inside a Kubernetes Pod out of the cloud providers
// mentioned in (1). In that case, the host.id will be later set to the full hostname.
func FetchHostID(ctx context.Context) string {
	log := slog.With("func", "fetchHostID")
	fetchers := []fetcher{
		{name: "AWS", fetch: ec2HostIDFetcher},
		{name: "Azure", fetch: azureHostIDFetcher},
		{name: "GCP", fetch: gcpHostIDFetcher},
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
			return id
		}
		log.Debug("didn't get host ID", "cause", err)
	}
	log.Debug("falling back to local host ID")
	hid, err := os.Hostname()
	if err != nil {
		log.Warn("getting host ID from host name", "error", err)
	}
	return hid
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

func linuxLocalMachineIDFetcher(_ context.Context) (string, error) {
	if result, err := os.ReadFile("/etc/machine-id"); err == nil || len(result) == 0 {
		return string(bytes.TrimSpace(result)), nil
	}

	if result, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil || len(result) == 0 {
		return string(bytes.TrimSpace(result)), nil
	} else {
		return "", fmt.Errorf("can't read host ID: %w", err)
	}

	TOMAR NODE DE kubernetes
	OBTENER HOSTNAME DE ENV
	obtener pod con dicho hostname
	obtener node para pod.nodeName
	obtener nodeInfo.machineId
}
