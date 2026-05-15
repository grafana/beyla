package webhook

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"golang.org/x/mod/semver"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/pipe/global"

	"github.com/grafana/beyla/v3/pkg/beyla"
	"github.com/grafana/beyla/v3/pkg/webhook/configmap"
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
	eligibleDeployments     *simplelru.LRU[string, *configmap.EligibleDeployment]
	eligibleDeploymentsMux  *sync.Mutex
	instrumentationManager  *InstrumentationManager
	externalWebhookUpdateNS atomic.Int64
	lastEligiblePodLaunchNS atomic.Int64
	stateWriteRequestNS     atomic.Int64
	rebuildRequestNS        atomic.Int64
	nodeName                string
	initialPodScan          atomic.Bool
}

const (
	stateConfigMapDebounceDelay     = 10 * time.Second
	rebuildDeploymentsDebounceDelay = 10 * time.Second
	debounceTickInterval            = time.Second
)

// For information on how this works see docs/design.md

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

	nodeName := OwnNodeName()

	stateWriter, err := NewStateConfigMapWriter(cfg, ctxInfo, nodeName)
	if err != nil {
		return nil, fmt.Errorf("error creating configmap state writer: %w", err)
	}
	if err := stateWriter.Init(context.Background()); err != nil {
		return nil, fmt.Errorf("error initializing configmap state writer: %w", err)
	}

	now := time.Now()

	eligible, err := simplelru.NewLRU[string, *configmap.EligibleDeployment](10_000, nil)

	if err != nil {
		return nil, fmt.Errorf("error initalizing the eligible deployments LRU: %w", err)
	}

	s := &Server{
		cfg:                    cfg,
		mutator:                mutator,
		bouncer:                bouncer,
		scanner:                NewInitialStateScanner(cfg.Injector.SDKPkgVersion),
		matcher:                matcher,
		logger:                 logger,
		ctxInfo:                ctxInfo,
		metrics:                metrics,
		podStateCache:          podStateCache,
		stateWriter:            stateWriter,
		eligibleDeployments:    eligible,
		eligibleDeploymentsMux: &sync.Mutex{},
		initialStateMux:        &sync.Mutex{},
		instrumentationManager: NewInstrumentationManager(cfg),
		nodeName:               nodeName,
	}

	s.lastEligiblePodLaunchNS.Store(now.UnixNano())
	s.externalWebhookUpdateNS.Store(now.UnixNano())
	s.initialPodScan.Store(true)

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

	if err := s.instrumentationManager.checkImageVolumeSupport(s.ctxInfo.K8sInformer); err != nil {
		return err
	}

	if s.podStateCache != nil {
		go s.subscribeStateCache(ctx)
	}

	if s.cfg.Injector.Webhook.UsesExternalWebhook() && s.stateWriter != nil {
		go s.runStateConfigMapWriter(ctx)
		go s.runEligibleDeploymentsRebuilder(ctx)
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

	errChan := s.setupWebhookServer(server)
	return s.waitForCancellation(ctx, server, errChan)
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

		if err := s.instrumentationManager.cleanupOldInstrumentationVersions(s.cfg.Injector.HostMountPath, oldestSDK); err != nil {
			s.logger.Warn("error cleaning up old instrumentation versions", "error", err)
		}
	}
	return nil
}

func (s *Server) getInitialState(ctx context.Context) error {
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
	s.initialPodScan.Store(false)
	s.logger.Debug("finished initial Kubernetes store scan")

	s.requestStateConfigMapWrite()

	return nil
}

func (s *Server) recordEligibleDeployment(a *ProcessInfo) {
	s.eligibleDeploymentsMux.Lock()
	defer s.eligibleDeploymentsMux.Unlock()

	key := deploymentKeyFromProcess(a)
	d := deploymentFromProcess(a)

	s.eligibleDeployments.Add(key, d)

	s.logger.Debug("added eligible deployment", "key", key)

	// Now request map update
	s.requestStateConfigMapWrite()
}

// requestStateConfigMapWrite marks the state ConfigMap as needing an update.
// Multiple callers within stateConfigMapDebounceDelay coalesce into a single
// write performed by runStateConfigMapWriter.
func (s *Server) requestStateConfigMapWrite() {
	if s.stateWriter == nil {
		return
	}
	s.stateWriteRequestNS.Store(time.Now().UnixNano())
}

// runStateConfigMapWriter writes the state ConfigMap once requests have been
// quiescent for stateConfigMapDebounceDelay.
func (s *Server) runStateConfigMapWriter(ctx context.Context) {
	ticker := time.NewTicker(debounceTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			requested := s.stateWriteRequestNS.Load()
			if requested == 0 {
				continue
			}
			if time.Since(time.Unix(0, requested)) < stateConfigMapDebounceDelay {
				continue
			}
			// Clear the request only if no newer request raced in. On CAS
			// failure the next tick observes the newer timestamp.
			if !s.stateWriteRequestNS.CompareAndSwap(requested, 0) {
				continue
			}
			if err := s.writeStateConfigMap(ctx); err != nil {
				s.logger.Warn("failed to write injector state ConfigMap", "error", err)
			}
		}
	}
}

// requestRebuildEligibleDeployments marks the eligible deployments map as
// needing a rebuild. Multiple callers within rebuildDeploymentsDebounceDelay
// coalesce into a single rebuild performed by runEligibleDeploymentsRebuilder.
func (s *Server) requestRebuildEligibleDeployments() {
	s.rebuildRequestNS.Store(time.Now().UnixNano())
}

// runEligibleDeploymentsRebuilder rebuilds the eligible deployments map once
// requests have been quiescent for rebuildDeploymentsDebounceDelay.
func (s *Server) runEligibleDeploymentsRebuilder(ctx context.Context) {
	ticker := time.NewTicker(debounceTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			requested := s.rebuildRequestNS.Load()
			if requested == 0 {
				continue
			}
			if time.Since(time.Unix(0, requested)) < rebuildDeploymentsDebounceDelay {
				continue
			}
			// Clear the request only if no newer request raced in. On CAS
			// failure the next tick observes the newer timestamp.
			if !s.rebuildRequestNS.CompareAndSwap(requested, 0) {
				continue
			}
			s.rebuildEligibleDeployments()
		}
	}
}

func (s *Server) writeStateConfigMap(ctx context.Context) error {
	if s.stateWriter == nil {
		return nil
	}

	s.logger.Debug("writing state config map")

	s.eligibleDeploymentsMux.Lock()
	defer s.eligibleDeploymentsMux.Unlock()
	eligible := make([]*configmap.EligibleDeployment, 0, s.eligibleDeployments.Len())
	eligible = append(eligible, s.eligibleDeployments.Values()...)
	sortEligible(eligible)

	config := configmap.InjectConfig{
		Discovery: s.cfg.Injector.Instrument,
		OtelExport: configmap.OtelExport{
			Endpoint: s.mutator.Endpoint(),
			Protocol: s.mutator.Protocol(),
		},
	}

	return s.stateWriter.Write(ctx, &config, eligible)
}

func sortEligible(eligible []*configmap.EligibleDeployment) {
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].Namespace != eligible[j].Namespace {
			return eligible[i].Namespace < eligible[j].Namespace
		}
		return eligible[i].Name < eligible[j].Name
	})
}

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

func (s *Server) isMyNodeEvent(event *informer.Event) bool {
	if s.nodeName == "" || event.Resource.Pod.NodeName == "" {
		return false
	}

	return s.nodeName == event.Resource.Pod.NodeName
}

func (s *Server) On(event *informer.Event) error {
	// ignoring updates on non-pod resources
	if event.Resource == nil || event.GetResource().GetPod() == nil {
		return nil
	}

	s.logger.Debug("new pod event", "pod", event.Resource, "type", event.Type)

	if s.cfg.Injector.Webhook.UsesExternalWebhook() && s.handleExternalWebhookEvent(event) {
		return nil
	}

	if !s.isMyNodeEvent(event) {
		return nil
	}

	if event.Type != informer.EventType_CREATED && event.Type != informer.EventType_UPDATED {
		return nil
	}

	if err := s.loadProcessStateIfNeccessary(); err != nil {
		return err
	}

	// It's important to consider the local process info here so that we are
	// not evaluating pods from other nodes, since Beyla gets cluster-wide info.
	attrs, err := s.processAttributes(event)

	if err != nil {
		return err
	}

	// These are processes that existed when Beyla booted, otherwise we won't find them
	// in attrs. In a sense this handles only the initial startup.
	for _, a := range attrs {
		s.handleNewProcessEvent(a)
	}
	return nil
}

func (s *Server) loadProcessStateIfNeccessary() error {
	if s.initialPodScan.Load() {
		if s.initialState == nil {
			if err := s.establishInitialProcessState(); err != nil {
				s.logger.Warn("unable to set initial process state", "error", err)
				return err
			}
		}
	}

	return nil
}

func (s *Server) processAttributes(event *informer.Event) ([]*ProcessInfo, error) {
	attrs := s.enrichProcessInfo(event.GetResource())
	if attrs == nil {
		if s.initialPodScan.Load() {
			if err := s.setOrUpdateInitialProcessState(); err != nil {
				s.logger.Warn("unable to update initial process state", "error", err)
				return nil, err
			}
			attrs = s.enrichProcessInfo(event.GetResource())
		}
		if attrs == nil {
			return nil, nil
		}
	}

	return attrs, nil
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
	s.initialStateMux.Lock()
	defer s.initialStateMux.Unlock()

	return s.enrichProcessInfoLocked(pod)
}

func (s *Server) enrichProcessInfoLocked(pod *informer.ObjectMeta) []*ProcessInfo {
	var res []*ProcessInfo

	for _, cnt := range pod.Pod.Containers {
		if procInfos, ok := s.initialState[cnt.Id]; ok {
			for _, p := range procInfos {
				attr := addMetadata(p, pod)
				res = append(res, attr)
			}
		}
	}

	return res
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

	s.eligibleDeploymentsMux.Lock()
	s.eligibleDeployments.Purge()
	s.eligibleDeploymentsMux.Unlock()

	s.initialStateMux.Lock()
	defer s.initialStateMux.Unlock()

	for cid := range s.initialState {
		if pod := s.store.PodByContainerID(cid); pod != nil {
			if attrs := s.enrichProcessInfoLocked(pod.Meta); attrs != nil {
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

func (s *Server) handleExternalWebhookEvent(event *informer.Event) bool {
	if event.Type == informer.EventType_CREATED || event.Type == informer.EventType_UPDATED {
		if s.isExternalWebhookEvent(event.GetResource()) {
			s.logger.Debug("external webhook event")
			if s.needsToUpdateEligibleDeployments() {
				s.requestRebuildEligibleDeployments()
			}
			return true
		} else {
			s.lastEligiblePodLaunchNS.Store(time.Now().UnixNano())
		}
	}

	return false
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
