package webhook

import (
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/mod/semver"

	"go.opentelemetry.io/obi/pkg/kube"

	"github.com/grafana/beyla/v3/pkg/beyla"
)

type InstrumentationManager struct {
	logger *slog.Logger
	cfg    *beyla.Config
}

func NewInstrumentationManager(cfg *beyla.Config) *InstrumentationManager {
	return &InstrumentationManager{
		logger: slog.With("component", "webhook.InstrumentationManager"),
		cfg:    cfg,
	}
}

func (i *InstrumentationManager) checkImageVolumeSupport(provider *kube.MetadataProvider) error {
	kubeClient, err := provider.KubeClient()
	if err != nil {
		return fmt.Errorf("can't get kubernetes client: %w", err)
	}
	serverVersion, err := kubeClient.Discovery().ServerVersion()
	if err != nil {
		return fmt.Errorf("can't get kubernetes server version: %w", err)
	}
	k8sVersion := fmt.Sprintf("v%s.%s.0", serverVersion.Major, strings.TrimRight(serverVersion.Minor, "+"))
	i.logger.Info("found Kubernetes version", "version", k8sVersion)
	if semver.Compare(k8sVersion, "v1.31.0") < 0 {
		return fmt.Errorf("image volume mounts require Kubernetes 1.31 or later, found %s.%s", serverVersion.Major, serverVersion.Minor)
	}
	return nil
}
