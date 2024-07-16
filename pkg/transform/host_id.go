package transform

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"

	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/contrib/detectors/aws/ec2"
	"go.opentelemetry.io/contrib/detectors/gcp"

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

}

func gcpHostIDFetcher(ctx context.Context) (string, error) {
	gcp.NewDetector()
}

func ec2HostIDFetcher(ctx context.Context) (string, error) {
	ec2ResourceDetector := ec2.NewResourceDetector()
	res, err := ec2ResourceDetector.Detect(ctx)
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

