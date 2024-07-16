package transform

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/contrib/detectors/aws/ec2"
	"go.opentelemetry.io/contrib/detectors/azure/azurevm"
	"go.opentelemetry.io/contrib/detectors/gcp"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
)

type hostIDFetcher func(context.Context) (string, error)

var cloudFetchers = map[string]hostIDFetcher{
	"EC2":   ec2HostIDFetcher,
	"GCP":   gcpHostIDFetcher,
	"Azure": azureHostIDFetcher,
}
var fallbackCloudFetcher = linuxLocalMachineIDFetcher

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

func linuxLocalMachineIDFetcher(ctx context.Context) (string, error) {
	if result, err := os.ReadFile("/etc/machine-id"); err == nil {
		return string(bytes.TrimSpace(result)), nil
	}

	if result, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
		return string(bytes.TrimSpace(result)), nil
	} else {
		return "", fmt.Errorf("can't read host ID: %w", err)
	}
}
