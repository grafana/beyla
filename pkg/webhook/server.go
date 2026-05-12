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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/mod/semver"
	appsv1 "k8s.io/api/apps/v1"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/transform"

	"github.com/grafana/beyla/v3/pkg/beyla"
)

// Server represents the webhook server
type Server struct {
	cfg                     *beyla.Config
	ctxInfo                 *global.ContextInfo
	mutator                 *PodMutator
	bouncer                 *PodBouncer
	scanner                 *LocalProcessScanner
	matcher                 *PodMatcher
	logger                  *slog.Logger
	store                   *kube.Store
	initialState            map[string][]*ProcessInfo
	initialStateMux         *sync.Mutex
	metrics                 *SDKInjectionMetrics
	podStateCache           *PodStateCache
	stateWriter             *StateConfigMapWriter
	eligibleDeployments     map[string]*EligibleDeployment
	eligibleDeploymentsMux  *sync.Mutex
	externalWebhookUpdateNS atomic.Int64
	lastEligiblePodLaunchNS atomic.Int64
}

// NewServer creates a new webhook server
func NewServer(cfg *beyla.Config, ctxInfo *global.ContextInfo) (*Server, error) {
	matcher := NewPodMatcher(cfg)
	var bouncer *PodBouncer

	logger := slog.Default().With("component", "webhook-server")

	var metrics *SDKInjectionMetrics
	var podStateCache *PodStateCache
	if ctxInfo.Prometheus != nil && cfg.InternalMetrics.Prometheus.Port != 0 {
		metrics = NewSDKInjectionMetrics()
		collectors := metrics.Collectors()
		if ownNode := OwnNodeName(); ownNode == "" {
			logger.Warn("state metrics unavailable: cannot determine node name (NODE_NAME unset and os.Hostname failed)")
		} else {
			podStateCache = NewPodStateCache(matcher, cfg, ownNode)
			collectors = append(collectors, podStateCache)
			logger.Info("registered beyla_injection_pods state metric collector")
		}
		ctxInfo.Prometheus.Register(cfg.InternalMetrics.Prometheus.Port, cfg.InternalMetrics.Prometheus.Path, collectors...)
	}

	mutator, err := NewPodMutator(cfg, matcher, metrics)
	if err != nil {
		return nil, err
	}

	if matcher.HasSelectionCriteria() && configuredToBounceDeployments(cfg) {
		bouncer, err = NewPodBouncer(ctxInfo, metrics)
		if err != nil {
			return nil, err
		}
	}

	stateWriter, err := NewStateConfigMapWriter(cfg, ctxInfo, OwnNodeName())
	if err != nil {
		logger.Warn("disabling injector state ConfigMap writer", "error", err)
	} else {
		err = stateWriter.Init(context.Background())
		if err != nil {
			logger.Warn("disabling injector state ConfigMap writer", "error", err)
		}
	}

	now := time.Now()

	s := &Server{
		cfg:                     cfg,
		mutator:                 mutator,
		bouncer:                 bouncer,
		scanner:                 NewInitialStateScanner(cfg.Injector.SDKPkgVersion),
		matcher:                 matcher,
		logger:                  logger,
		ctxInfo:                 ctxInfo,
		metrics:                 metrics,
		podStateCache:           podStateCache,
		stateWriter:             stateWriter,
		eligibleDeployments:     map[string]*EligibleDeployment{},
		eligibleDeploymentsMux:  &sync.Mutex{},
		initialStateMux:         &sync.Mutex{},
		lastEligiblePodLaunchNS: atomic.Int64{},
		externalWebhookUpdateNS: atomic.Int64{},
	}

	s.lastEligiblePodLaunchNS.Store(now.UnixNano())
	s.externalWebhookUpdateNS.Store(now.UnixNano())

	return s, nil
}

func (s *Server) makeHTTPServer() *http.Server {
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

	return server
}

func configuredToBounceDeployments(cfg *beyla.Config) bool {
	return !cfg.Injector.NoAutoRestart && !cfg.Injector.Webhook.UsesExternalWebhook()
}

// Start starts the webhook server
func (s *Server) Start(ctx context.Context) error {
	var server *http.Server
	if !s.cfg.Injector.Webhook.UsesExternalWebhook() {
		if err := waitForTLSFiles(ctx, s.cfg.Injector.Webhook.CertPath, s.cfg.Injector.Webhook.KeyPath, s.cfg.Injector.Webhook.Timeout, time.Second); err != nil {
			return fmt.Errorf("webhook TLS not ready: %w", err)
		}
		server = s.makeHTTPServer()
	}

	s.logger.Info("starting webhook server", "port", s.cfg.Injector.Webhook.Port, "certPath", s.cfg.Injector.Webhook.CertPath)

	if err := s.checkImageVolumeSupport(s.ctxInfo.K8sInformer); err != nil {
		return err
	}

	if s.podStateCache != nil {
		go s.subscribeStateCache(ctx)
	}

	if s.matcher.HasSelectionCriteria() {
		s.logger.Info("starting initial state scanning")
		go func() {
			err := s.getInitialState(ctx)
			if err != nil {
				s.logger.Error("encountered error during initial state scan", "error", err)
			}
		}()
	}

	// Start internal metrics HTTP server if configured
	if s.cfg.InternalMetrics.Prometheus.Port != 0 && s.ctxInfo.Prometheus != nil {
		go s.ctxInfo.Prometheus.StartHTTP(ctx)
	}

	var errChan chan error
	if !s.cfg.Injector.Webhook.UsesExternalWebhook() {
		// Start server in a goroutine
		errChan = make(chan error, 1)
		go func() {
			if err := server.ListenAndServeTLS(s.cfg.Injector.Webhook.CertPath, s.cfg.Injector.Webhook.KeyPath); err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("webhook server failed: %w", err)
			}
			close(errChan)
		}()
	}
	return s.waitForCancellation(ctx, server, errChan)
}

func (s *Server) waitForCancellation(ctx context.Context, server *http.Server, errChan chan error) error {
	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		s.logger.Debug("shutting down webhook server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if !s.cfg.Injector.Webhook.UsesExternalWebhook() {
			if err := server.Shutdown(shutdownCtx); err != nil {
				return fmt.Errorf("webhook server shutdown failed: %w", err)
			}
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

func (s *Server) setOrUpdateInitialProcessState() error {
	s.initialStateMux.Lock()
	defer s.initialStateMux.Unlock()
	initialState, err := s.scanner.FindExistingProcesses()
	if err != nil {
		return fmt.Errorf("finding initial process state: %w", err)
	}
	s.initialState = initialState

	return nil
}

func (s *Server) establishInitialProcessState() error {
	if err := s.setOrUpdateInitialProcessState(); err != nil {
		return err
	}

	if !s.cfg.Injector.UsesImageVolume() && s.cfg.Injector.ManageSDKVersions {
		oldestSDK := s.scanner.OldestSDKVersion()
		// we could be downgrading the SDK, check if the oldest version is not
		// newer than what we are launching with now
		if semver.Compare(oldestSDK, s.cfg.Injector.SDKPkgVersion) > 0 {
			oldestSDK = s.cfg.Injector.SDKPkgVersion
		}

		if err := s.cleanupOldInstrumentationVersions(s.cfg.Injector.HostMountPath, oldestSDK); err != nil {
			s.logger.Warn("error cleaning up old instrumentation versions", "error", err)
		}
	}
	return nil
}

func (s *Server) checkImageVolumeSupport(provider *kube.MetadataProvider) error {
	if s.cfg.Injector.UsesImageVolume() {
		kubeClient, err := provider.KubeClient()
		if err != nil {
			return fmt.Errorf("can't get kubernetes client: %w", err)
		}
		serverVersion, err := kubeClient.Discovery().ServerVersion()
		if err != nil {
			return fmt.Errorf("can't get kubernetes server version: %w", err)
		}
		k8sVersion := fmt.Sprintf("v%s.%s.0", serverVersion.Major, strings.TrimRight(serverVersion.Minor, "+"))
		s.logger.Info("found Kubernetes version", "version", k8sVersion)
		if semver.Compare(k8sVersion, "v1.31.0") < 0 {
			return fmt.Errorf("image volume mounts require Kubernetes 1.31 or later, found %s.%s", serverVersion.Major, serverVersion.Minor)
		}
	}

	return nil
}

// subscribeStateCache subscribes the pod state cache to the kube informer store.
func (s *Server) subscribeStateCache(ctx context.Context) {
	if !s.ctxInfo.K8sInformer.IsKubeEnabled() {
		return
	}
	store, err := s.ctxInfo.K8sInformer.Get(ctx)
	if err != nil {
		s.logger.Error("state metrics unavailable: cannot subscribe to k8s informer", "error", err)
		return
	}
	// Subscribe delivers all existing pods synchronously as CREATED events before
	// returning. SYNC_FINISHED is not forwarded to late subscribers, so we mark
	// the cache as ready immediately after Subscribe returns.
	store.Subscribe(s.podStateCache)
	s.podStateCache.markSynced()
}

func (s *Server) getInitialState(ctx context.Context) error {
	if err := s.establishInitialProcessState(); err != nil {
		return err
	}

	provider := s.ctxInfo.K8sInformer

	if !provider.IsKubeEnabled() {
		return nil
	}

	store, err := provider.Get(ctx)
	if err != nil {
		return fmt.Errorf("instantiating Kubernetes metadata scanner: %w", err)
	}
	s.store = store

	// Subscribe synchronously: the store delivers all existing pods as CREATED
	// events before returning. After this call our eligibleDeployments map
	// reflects the initial state, and we can persist it. Future events still
	// flow through the registered observer asynchronously.
	store.Subscribe(s)

	if s.stateWriter != nil {
		if err := s.writeStateConfigMap(ctx); err != nil {
			s.logger.Warn("failed to write injector state ConfigMap", "error", err)
		}
	}

	return nil
}

func deploymentFromProcess(a *ProcessInfo) *EligibleDeployment {
	namespace := a.metadata[services.AttrNamespace]
	deployment := a.metadata[attr.K8sDeploymentName.Prom()]

	language := languageLabel(a.kind)

	return &EligibleDeployment{
		Namespace:  namespace,
		Kind:       "Deployment",
		Deployment: deployment,
		Language:   language,
	}
}

func deploymentKeyFromProcess(a *ProcessInfo) string {
	namespace := a.metadata[services.AttrNamespace]
	deployment := a.metadata[attr.K8sDeploymentName.Prom()]

	return mutationKey(namespace, deployment)
}

func (s *Server) removeEligibleDeployment(a *ProcessInfo) {
	s.eligibleDeploymentsMux.Lock()
	defer s.eligibleDeploymentsMux.Unlock()

	key := deploymentKeyFromProcess(a)
	delete(s.eligibleDeployments, key)
}

func (s *Server) recordEligibleDeployment(a *ProcessInfo) {
	s.eligibleDeploymentsMux.Lock()
	defer s.eligibleDeploymentsMux.Unlock()

	key := deploymentKeyFromProcess(a)
	d := deploymentFromProcess(a)

	s.eligibleDeployments[key] = d
}

func (s *Server) writeStateConfigMap(ctx context.Context) error {
	s.eligibleDeploymentsMux.Lock()
	defer s.eligibleDeploymentsMux.Unlock()
	eligible := make([]*EligibleDeployment, 0, len(s.eligibleDeployments))
	for _, d := range s.eligibleDeployments {
		eligible = append(eligible, d)
	}

	config := InjectConfig{
		Criteria: s.cfg.Injector.Instrument,
	}

	return s.stateWriter.Write(ctx, &config, eligible)
}

func (s *Server) ID() string { return uuid.NewString() }

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
	lang := languageLabel(a.kind)
	if err := s.bouncer.RestartDeployment(context.Background(), namespace, deployment, "Deployment", lang); err != nil {
		s.logger.Info("failed to restart pods", "error", err)
	}
}

func (s *Server) On(event *informer.Event) error {
	// ignoring updates on non-pod resources
	if event.Resource == nil || event.GetResource().GetPod() == nil {
		return nil
	}

	s.logger.Debug("new pod event", "pod", event.Resource, "type", event.Type)

	if event.Type == informer.EventType_CREATED || event.Type == informer.EventType_UPDATED {
		if s.isExternalWebhookEvent(event.GetResource()) {
			if s.needsToUpdateEligibleDeployments() {
				s.rebuildEligibleDeployments()
				s.externalWebhookUpdateNS.Store(time.Now().UnixNano())
			}
			return nil
		} else {
			s.lastEligiblePodLaunchNS.Store(time.Now().UnixNano())
		}
	}

	// It's important to consider the local process info here so that we are
	// not evaluating pods from other nodes, since Beyla gets cluster-wide info.
	attrs := s.enrichProcessInfo(event.GetResource())
	if attrs == nil {
		return nil
	}

	if event.Type == informer.EventType_DELETED {
		s.logger.Debug("removed pod", "pod", event.Resource)
		for _, a := range attrs {
			s.handleDeletedProcessEvent(a)
		}

		return nil
	}

	if event.Type != informer.EventType_CREATED && event.Type != informer.EventType_UPDATED {
		return nil
	}

	for _, a := range attrs {
		s.handleNewProcessEvent(a)
	}
	return nil
}

func (s *Server) handleDeletedProcessEvent(a *ProcessInfo) {
	s.removeEligibleDeployment(a)
}

func (s *Server) handleNewProcessEvent(a *ProcessInfo) {
	if s.mutator.AlreadyInstrumented(a) {
		// If this pod was instrumented, but the new Beyla config says don't anymore
		// we bounce the pods to undo the instrumentation
		if _, matched := s.matcher.MatchProcessInfo(a); matched {
			return
		}
		if configuredToBounceDeployments(s.cfg) {
			s.restartDeployment(a)
		}
		return
	}

	// It's important to check here for the SDK supported programming languages.
	// Go would be the killer here, since many of the Kubernetes services are written in
	// Go, and we don't want to say bounce coredns.
	if !s.mutator.CanInstrument(a.kind) || s.mutator.PreloadsSomethingElse(a) {
		s.logger.Debug("ignoring process because of unsupported programming language or LD_PRELOAD", "info", a)
		return
	}

	// The match process info only relies on the initial process state
	// so it will not find any info on new processes. This is by design, since
	// we don't want to do work for processes we've seen after we've launched,
	// they'll get seen by the webhook when the pods start, before there's info.
	if _, matched := s.matcher.MatchProcessInfo(a); matched {
		s.recordEligibleDeployment(a)
		if configuredToBounceDeployments(s.cfg) {
			s.restartDeployment(a)
		}
	}
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

	s.logger.Debug("found SDK versions", "entries", entries)

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

func (s *Server) isExternalWebhookEvent(info *informer.ObjectMeta) bool {
	namespace := info.Namespace
	deploymentName := ""
	for _, owner := range info.Pod.Owners {
		switch owner.Kind {
		case "Deployment":
			deploymentName = owner.Name
		case "ReplicaSet":
			deploymentName = deploymentNameFromReplicaSet(owner.Name, info.Labels)
		}
		if deploymentName != "" {
			break
		}
	}

	if namespace != "" && deploymentName != "" {
		key := mutationKey(namespace, deploymentName)
		return key == s.cfg.Injector.Webhook.ExternalWebhook
	}

	return false
}

func deploymentNameFromReplicaSet(replicaSetName string, labels map[string]string) string {
	podTemplateHash := labels[appsv1.DefaultDeploymentUniqueLabelKey]
	suffix := "-" + podTemplateHash
	if podTemplateHash != "" && strings.HasSuffix(replicaSetName, suffix) {
		return strings.TrimSuffix(replicaSetName, suffix)
	}
	return replicaSetName
}

func (s *Server) needsToUpdateEligibleDeployments() bool {
	lastUpdate := s.externalWebhookUpdateNS.Load()
	lastLaunch := s.lastEligiblePodLaunchNS.Load()

	return lastLaunch >= lastUpdate
}

func (s *Server) rebuildEligibleDeployments() {
	if err := s.setOrUpdateInitialProcessState(); err != nil {
		s.logger.Warn("unable to update initial process state", "error", err)
		return
	}

	s.initialStateMux.Lock()
	defer s.initialStateMux.Unlock()

	for cid := range s.initialState {
		if pod := s.store.PodByContainerID(cid); pod != nil {
			if attrs := s.enrichProcessInfo(pod.Meta); attrs != nil {
				for _, a := range attrs {
					s.handleNewProcessEvent(a)
				}
			}
		}
	}

	if err := s.writeStateConfigMap(context.Background()); err != nil {
		s.logger.Warn("unable to update config map with new process state", "error", err)
	}
	s.externalWebhookUpdateNS.Store(time.Now().UnixNano())
}
