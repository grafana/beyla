package kube

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/grafana/beyla-k8s-cache/pkg/informer"
	"github.com/grafana/beyla-k8s-cache/pkg/meta"
)

const (
	kubeConfigEnvVariable  = "KUBECONFIG"
	defaultResyncTime      = 30 * time.Minute
	defaultSyncTimeout     = 30 * time.Second
	IndexPodByContainerIDs = "idx_pod_by_container"
	IndexIP                = "idx_ip"
	typeNode               = "Node"
	typePod                = "Pod"
	typeService            = "Service"
)

func klog() *slog.Logger {
	return slog.With("component", "kube.Metadata")
}

type MetadataObserver interface {
	ID() string
	On(event *informer.Event)
}

type MetadataNotifier interface {
	Subscribe(observer meta.Observer)
	Unsubscribe(observer meta.Observer)
	Notify(event *informer.Event)
}

// InformersMetadata stores an in-memory copy of the different Kubernetes objects whose metadata is relevant to us.
type InformersMetadata struct {
	log *slog.Logger

	informers *meta.Informers

	SyncTimeout  time.Duration
	resyncPeriod time.Duration
}

func NewInformersMetadata(ctx context.Context, kubeConfigPath string) (*InformersMetadata, error) {
	// TODO: Add a context timeout to the initialization of the informers
	informers, err := meta.InitInformers(ctx, kubeConfigPath, defaultResyncTime)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize informers: %w", err)
	}

	imd := &InformersMetadata{
		log:          klog(),
		informers:    informers,
		SyncTimeout:  defaultSyncTimeout,
		resyncPeriod: defaultResyncTime,
	}
	return imd, nil
}

func (k *InformersMetadata) Subscribe(observer meta.Observer) {
	k.informers.Subscribe(observer)
}

func (k *InformersMetadata) Unsubscribe(observer meta.Observer) {
	k.informers.Unsubscribe(observer)
}

func (k *InformersMetadata) Notify(event *informer.Event) {
	k.informers.Notify(event)
}
