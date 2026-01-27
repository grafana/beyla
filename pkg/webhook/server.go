package webhook

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/mod/semver"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/transform"

	"github.com/grafana/beyla/v2/pkg/beyla"
)

// Server represents the webhook server
type Server struct {
	cfg          *beyla.Config
	ctxInfo      *global.ContextInfo
	mutator      *PodMutator
	bouncer      *PodBouncer
	scanner      *LocalProcessScanner
	matcher      *PodMatcher
	logger       *slog.Logger
	store        *kube.Store
	initialState map[string][]*ProcessInfo
}

// NewServer creates a new webhook server
func NewServer(cfg *beyla.Config, ctxInfo *global.ContextInfo) (*Server, error) {
	matcher := NewPodMatcher(cfg)
	var bouncer *PodBouncer

	mutator, err := NewPodMutator(cfg, matcher)
	if err != nil {
		return nil, err
	}

	if matcher.HasSelectionCriteria() {
		bouncer, err = NewPodBouncer(ctxInfo)
		if err != nil {
			return nil, err
		}
	}

	return &Server{
		cfg:     cfg,
		mutator: mutator,
		bouncer: bouncer,
		scanner: NewInitialStateScanner(),
		matcher: matcher,
		logger:  slog.Default().With("component", "webhook-server"),
		ctxInfo: ctxInfo,
	}, nil
}

// Start starts the webhook server
func (s *Server) Start(ctx context.Context) error {
	if err := waitForTLSFiles(ctx, s.cfg.Injector.Webhook.CertPath, s.cfg.Injector.Webhook.KeyPath, s.cfg.Injector.Webhook.Timeout, time.Second); err != nil {
		return fmt.Errorf("webhook TLS not ready: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", s.mutator.HandleMutate)
	mux.HandleFunc("/health", s.mutator.HealthCheck)
	mux.HandleFunc("/readyz", s.mutator.HealthCheck)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", s.cfg.Injector.Webhook.Port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Load TLS certificates
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	server.TLSConfig = tlsConfig

	s.logger.Info("starting webhook server", "port", s.cfg.Injector.Webhook.Port, "certPath", s.cfg.Injector.Webhook.CertPath)

	if s.matcher.HasSelectionCriteria() && !s.cfg.Injector.NoAutoRestart {
		s.logger.Info("starting initial state scanning")
		go func() {
			err := s.getInitialState(ctx)
			if err != nil {
				s.logger.Error("encountered error during initial state scan", "error", err)
			}
		}()
	}

	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := server.ListenAndServeTLS(s.cfg.Injector.Webhook.CertPath, s.cfg.Injector.Webhook.KeyPath); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("webhook server failed: %w", err)
		}
		close(errChan)
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		s.logger.Debug("shutting down webhook server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
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
			return errors.New("TLS files not found before timeout")
		case <-time.After(poll):
		}
	}
}

func (s *Server) getInitialState(ctx context.Context) error {
	provider := s.ctxInfo.K8sInformer
	store, err := provider.Get(ctx)
	if err != nil {
		return fmt.Errorf("instantiating Kubernetes metadata scanner: %w", err)
	}
	s.store = store
	initialState, err := s.scanner.FindExistingProcesses()
	if err != nil {
		return fmt.Errorf("finding initial process state: %w", err)
	}
	s.initialState = initialState

	if oldestSDK, err := s.scanner.OldestSDKVersion(); err != nil {
		// we could be downgrading the SDK, check if the oldest version is not
		// newer than what we are launching with now
		if semver.Compare(oldestSDK, s.cfg.Injector.SDKPkgVersion) > 0 {
			oldestSDK = s.cfg.Injector.SDKPkgVersion
		}

		if err := s.cleanupOldInstrumentationVersions(s.cfg.Injector.HostMountPath, oldestSDK); err != nil {
			s.logger.Warn("error cleaning up old instrumentation versions", "error", err)
		}
	}

	go store.Subscribe(s)

	return nil
}

func (s *Server) ID() string { return "unique-webhook-server-id" }

func (s *Server) restartDeployment(a *ProcessInfo) {
	namespace := a.metadata[services.AttrNamespace]
	deployment := a.metadata[attr.K8sDeploymentName.Prom()]

	if !s.bouncer.CanBeBounced(namespace, deployment) {
		s.logger.Debug("ignoring non kubernetes process", "info", a)
		return
	}
	if s.bouncer.AlreadyBounced(namespace, deployment) {
		s.logger.Debug("already restarted", "namespace", namespace, "deployment", deployment)
		return
	}

	if err := s.bouncer.RestartDeployment(context.Background(), namespace, deployment); err != nil {
		s.logger.Info("failed to restart pods", "error", err)
	}
}

func (s *Server) On(event *informer.Event) error {
	// ignoring updates on non-pod resources
	if event.Resource == nil || event.GetResource().GetPod() == nil {
		return nil
	}
	switch event.Type {
	case informer.EventType_CREATED, informer.EventType_UPDATED:
		s.logger.Debug("new pod", "pod", event.Resource)
		// It's important to consider the local process info here
		// so that we are not evaluating pods from other nodes, since
		// Beyla gets the cluster wide info.
		if attrs := s.enrichProcessInfo(event.GetResource()); attrs != nil {
			for _, a := range attrs {
				// It's important to check here for the SDK supported programming languages.
				// Go would be the killer here, since many of the Kubernetes services are written in
				// Go, and we don't want to say bounce coredns.
				switch s.mutator.AlreadyInstrumented(a) {
				case false:
					if s.mutator.CanInstrument(a.kind) && !s.mutator.PreloadsSomethingElse(a) {
						if _, matched := s.matcher.MatchProcessInfo(a); matched {
							s.restartDeployment(a)
						}
					} else {
						s.logger.Debug("ignoring process because of unsupported programming language or LD_PRELOAD", "info", a)
					}
				case true:
					// If this pod was instrumented, but the new Beyla config says don't anymore
					// we bounce the pods to undo the instrumentation
					if _, matched := s.matcher.MatchProcessInfo(a); !matched {
						s.restartDeployment(a)
					}
				}
			}
		}
	}
	return nil
}

// This function will return nil if the pod containers didn't match, which
// typically means it's a pod from a different node
func (s *Server) enrichProcessInfo(pod *informer.ObjectMeta) []*ProcessInfo {
	var res []*ProcessInfo

	for _, cnt := range pod.Pod.Containers {
		if procInfos, ok := s.initialState[cnt.Id]; ok {
			for _, p := range procInfos {
				attr := s.addMetadata(p, pod)
				res = append(res, attr)
			}
		}
	}

	return res
}

func topOwner(owners []*informer.Owner) *informer.Owner {
	if len(owners) == 0 {
		return nil
	}
	return owners[len(owners)-1]
}

// Adds the kubernetes metadata to the matched local process
func (s *Server) addMetadata(pp *ProcessInfo, info *informer.ObjectMeta) *ProcessInfo {
	ownerName := info.Name
	if info.Pod != nil {
		if topOwner := topOwner(info.Pod.Owners); topOwner != nil {
			ownerName = topOwner.Name
		}
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
	return ret
}

// cleanupOldInstrumentationVersions removes instrumentation directories
// older than the specified minimum version
func (s *Server) cleanupOldInstrumentationVersions(instrumentDir string, minVersion string) error {
	if !semver.IsValid(minVersion) {
		return fmt.Errorf("invalid minimum version: %s", minVersion)
	}

	entries, err := os.ReadDir(instrumentDir)
	if err != nil {
		return fmt.Errorf("failed to read directory %s: %w", instrumentDir, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		version := entry.Name()

		// Skip if the directory not a valid semver in the instrumentation volume
		if !semver.IsValid(version) {
			s.logger.Debug("ignoring directory in the instrumentation path", "dir", entry.Name())
			continue
		}

		if semver.Compare(version, minVersion) < 0 {
			dirPath := filepath.Join(instrumentDir, entry.Name())
			if err := os.RemoveAll(dirPath); err != nil {
				return fmt.Errorf("failed to remove directory %s: %w", dirPath, err)
			}
			s.logger.Info("removed old instrumentation", "version", entry.Name())
		}
	}

	return nil
}
