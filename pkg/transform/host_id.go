package transform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"

	"go.opentelemetry.io/contrib/detectors/aws/ec2"
	"go.opentelemetry.io/contrib/detectors/azure/azurevm"
	"go.opentelemetry.io/contrib/detectors/gcp"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
)

type hostIDFetcher func(context.Context) (string, error)

type fetcher struct {
	name string
	fetch hostIDFetcher
}

func fetchHostID(ctx context.Context) (string, error) {
	log := klog().With("func", "fetchHostID")
	fetchers := []fetcher{
		{name: "AWS", fetch: ec2HostIDFetcher},
		{name: "Azure", fetch: azureHostIDFetcher},
		{name: "GCP", fetch: gcpHostIDFetcher},
		{name: "fallback", fetch: linuxLocalMachineIDFetcher},
	}
	for _, f := range fetchers {
		log := log.With("fetcher", f.name)
		log.Debug("trying to fetch host ID")
		if id, err := f.fetch(ctx); err != nil {
			log.Debug("didn't get host ID", "error", err)
		} else {
			log.Info("got host ID", "hostID", id)
			return id, nil
		}
	}
	return "", errors.New("could not find host ID")
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
	if result, err := os.ReadFile("/etc/machine-id"); err == nil {
		return string(bytes.TrimSpace(result)), nil
	}

	if result, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
		return string(bytes.TrimSpace(result)), nil
	} else {
		return "", fmt.Errorf("can't read host ID: %w", err)
	}
}
