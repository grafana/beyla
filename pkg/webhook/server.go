package webhook

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/transform"
	"k8s.io/client-go/kubernetes"
)

// Server represents the webhook server
type Server struct {
	Port         int
	CertPath     string
	KeyPath      string
	mutator      *PodMutator
	logger       *slog.Logger
	server       *http.Server
	ctxInfo      *global.ContextInfo
	store        *kube.Store
	initialState map[string][]*ProcessInfo
	bounced      map[string]*ProcessInfo
	criteria     []services.Selector
	kubeClient   kubernetes.Interface
}

// NewServer creates a new webhook server
func NewServer(cfg *beyla.Config, ctxInfo *global.ContextInfo) (*Server, error) {
	mutator, err := NewPodMutator(cfg)
	if err != nil {
		return nil, err
	}

	kubeClient, err := ctxInfo.K8sInformer.KubeClient()
	if err != nil {
		return nil, fmt.Errorf("can't get kubernetes client: %w", err)
	}

	return &Server{
		Port:       cfg.Injector.Webhook.Port,
		CertPath:   cfg.Injector.Webhook.CertPath,
		KeyPath:    cfg.Injector.Webhook.KeyPath,
		mutator:    mutator,
		logger:     slog.Default().With("component", "webhook-server"),
		ctxInfo:    ctxInfo,
		criteria:   discover.NormalizeGlobCriteria(cfg.Injector.Instrument),
		bounced:    map[string]*ProcessInfo{},
		kubeClient: kubeClient,
	}, nil
}

// Start starts the webhook server
func (s *Server) Start(ctx context.Context) error {
	if err := waitForTLSFiles(ctx, s.CertPath, s.KeyPath, 30*time.Second, time.Second); err != nil {
		return fmt.Errorf("webhook tls not ready: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", s.mutator.HandleMutate)
	mux.HandleFunc("/health", s.mutator.HealthCheck)
	mux.HandleFunc("/readyz", s.mutator.HealthCheck)

	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.Port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Load TLS certificates
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	s.server.TLSConfig = tlsConfig

	s.logger.Info("starting webhook server", "port", s.Port, "certPath", s.CertPath, "criteria", s.criteria)

	if len(s.criteria) > 0 {
		s.logger.Info("starting initial state scanning")
		go func() {
			err := s.InitialStateScanner(ctx)
			if err != nil {
				s.logger.Error("encountered error during initial state scan", "error", err)
			}
		}()
	}

	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServeTLS(s.CertPath, s.KeyPath); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("webhook server failed: %w", err)
		}
		close(errChan)
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		s.logger.Info("shutting down webhook server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := s.server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("webhook server shutdown failed: %w", err)
		}
		// Don't return ctx.Err() as an error - graceful shutdown is expected
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil
		}
		return ctx.Err()
	case err := <-errChan:
		if err != nil {
			return err
		}
		return nil
	}
}

// Stop gracefully stops the webhook server
func (s *Server) Stop(ctx context.Context) error {
	if s.server == nil {
		return nil
	}

	s.logger.Info("stopping webhook server")
	return s.server.Shutdown(ctx)
}

// waitForTLSFiles blocks until both TLS cert and key exist or context/timeout expires.
func waitForTLSFiles(ctx context.Context, certPath, keyPath string, timeout, poll time.Duration) error {
	deadline := time.After(timeout)
	for {
		if _, err := os.Stat(certPath); err == nil {
			if _, err := os.Stat(keyPath); err == nil {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return errors.New("tls files not found before timeout")
		case <-time.After(poll):
		}
	}
}

func (s *Server) InitialStateScanner(ctx context.Context) error {
	provider := s.ctxInfo.K8sInformer
	store, err := provider.Get(ctx)
	if err != nil {
		return fmt.Errorf("instantiating Kubernetes metadata scanner: %w", err)
	}
	s.store = store
	initialState, err := findExistingProcesses()
	if err != nil {
		return fmt.Errorf("finding initial process state: %w", err)
	}
	s.initialState = initialState

	go store.Subscribe(s)

	return nil
}

func (s *Server) ID() string { return "unique-webhook-server-id" }

func (s *Server) On(event *informer.Event) error {
	// ignoring updates on non-pod resources
	if event.Resource == nil || event.GetResource().GetPod() == nil {
		return nil
	}
	switch event.Type {
	case informer.EventType_CREATED, informer.EventType_UPDATED:
		s.logger.Debug("New pod", "info", event.Resource)
		if attrs := s.processAttrs(event.GetResource()); attrs != nil {
			for _, a := range attrs {
				// add check for already mutated, look at the envs and ignore
				if s.mutator.CanInstrument(a.kind) && !s.mutator.AlreadyInstrumented(a.env) {
					if matchProcessInfo(a, s.criteria) {
						key := mutationKey(a)
						if key == "" {
							s.logger.Debug("ignoring non kubernetes process", "info", a)
							continue
						}
						if _, ok := s.bounced[key]; ok {
							s.logger.Debug("already restarted", "key", key, "node", event.Resource.Pod.NodeName)
							continue
						}
						deployment := a.metadata[attr.K8sDeploymentName.Prom()]
						if deployment != "" {
							s.logger.Info("I'm going to restart", "deployment", deployment, "event", event.Resource, "info", a)
							s.bounced[key] = a
							if err := restartDeployment(context.Background(), s.kubeClient, a.metadata[services.AttrNamespace], a.metadata[attr.K8sDeploymentName.Prom()]); err != nil {
								s.logger.Info("failed to restart pods", "error", err)
							}
						} else {
							s.logger.Debug("not restarting, not a deployment", "info", a)
						}
					}
				} else {
					s.logger.Debug("ignoring process for unsupported type", "info", a)
				}
			}
		}
	}
	return nil
}

func mutationKey(a *ProcessInfo) string {
	return a.metadata[attr.K8sDeploymentName.Prom()] + a.metadata[services.AttrNamespace]
}

func topOwner(pod *informer.PodInfo) *informer.Owner {
	if pod == nil || len(pod.Owners) == 0 {
		return nil
	}
	return pod.Owners[len(pod.Owners)-1]
}

func (s *Server) processAttrs(pod *informer.ObjectMeta) []*ProcessInfo {
	res := []*ProcessInfo{}

	for _, cnt := range pod.Pod.Containers {
		if procInfos, ok := s.initialState[cnt.Id]; ok {
			for _, p := range procInfos {
				attr := s.addMetadata(p, pod, cnt.Id)
				res = append(res, attr)
			}
		}
	}

	return res
}

func (s *Server) addMetadata(pp *ProcessInfo, info *informer.ObjectMeta, containerID string) *ProcessInfo {
	ownerName := info.Name
	if topOwner := topOwner(info.Pod); topOwner != nil {
		ownerName = topOwner.Name
	}

	ret := pp

	ret.metadata = map[string]string{
		services.AttrNamespace: info.Namespace,
		services.AttrPodName:   info.Name,
		services.AttrOwnerName: ownerName,
	}
	ret.podLabels = info.Labels
	ret.podAnnotations = info.Annotations

	// add any other owner name (they might be several, e.g. replicaset and deployment)
	for _, owner := range info.Pod.Owners {
		ret.metadata[transform.OwnerLabelName(owner.Kind).Prom()] = owner.Name
	}
	if containerID == "" {
		return ret
	}
	for _, podContainer := range info.Pod.Containers {
		if podContainer.Id == containerID {
			ret.metadata[services.AttrContainerName] = podContainer.Name
			break
		}
	}
	return ret
}
