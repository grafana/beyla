// See docs/design.md for the architecture overview
package webhook

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/pipe/global"

	"github.com/grafana/beyla/v3/pkg/beyla"
	"github.com/grafana/beyla/v3/pkg/webhook/configmap"
)

// Server communicates with the external webhook server to coordinate who should
// instrument/decorate/restart injected pods
// TODO: rename
type Server struct {
	cfg                     *beyla.Config
	ctxInfo                 *global.ContextInfo
	mutator                 *PodMutator
	scanner                 *LocalProcessScanner
	matcher                 *PodMatcher
	logger                  *slog.Logger
	store                   *kube.Store
	initialState            map[string][]*ProcessInfo
	initialStateMux         sync.Mutex
	metrics                 *SDKInjectionMetrics
	podStateCache           *PodStateCache
	stateWriter             *StateConfigMapWriter
	eligibleDeployments     *simplelru.LRU[string, *configmap.EligibleDeployment]
	eligibleDeploymentsMux  sync.Mutex
	instrumentationManager  *InstrumentationManager
	externalWebhookUpdateNS atomic.Int64
	lastEligiblePodLaunchNS atomic.Int64
	stateWriteRequestNS     atomic.Int64
	rebuildRequestNS        atomic.Int64
	nodeName                string
	initialPodScan          atomic.Bool
	uuid                    string
	stateCfg                *configmap.InjectConfig
	stateHash               string
}

func (s *Server) ID() string { return s.uuid }

const (
	stateConfigMapDebounceDelay     = 10 * time.Second
	rebuildDeploymentsDebounceDelay = 10 * time.Second
	debounceTickInterval            = time.Second
	maxEligibleDeployments          = 10_000
)

// NewServer creates a new webhook server
func NewServer(cfg *beyla.Config, ctxInfo *global.ContextInfo) (*Server, error) {
	matcher := NewPodMatcher(cfg)

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

	nodeName := OwnNodeName()

	stateCfg := configmap.InjectConfig{
		NodeName:  nodeName,
		Discovery: cfg.Injector.Instrument,
		OtelExport: configmap.OtelExport{
			Endpoint: mutator.Endpoint(),
			Protocol: mutator.Protocol(),
		},
		ExportedSignals:    cfg.Injector.ExportedSignals,
		ImageVolumeVersion: cfg.Injector.ImageVolumeVersion,
		DefaultSampler:     cfg.Injector.DefaultSampler,
		Propagators:        cfg.Injector.Propagators,
		Resources:          cfg.Injector.Resources,
	}

	stateHash := stateCfg.Hash()

	logger.Info("SDK injection config established", "hash", stateHash)

	stateWriter, err := NewStateConfigMapWriter(ctxInfo, nodeName)
	if err != nil {
		return nil, fmt.Errorf("error creating configmap state writer: %w", err)
	}
	if err := stateWriter.Init(context.Background()); err != nil {
		return nil, fmt.Errorf("error initializing configmap state writer: %w", err)
	}

	now := time.Now()

	eligible, err := simplelru.NewLRU[string, *configmap.EligibleDeployment](maxEligibleDeployments, nil)
	if err != nil {
		return nil, fmt.Errorf("error initalizing the eligible deployments LRU: %w", err)
	}

	s := &Server{
		cfg:                    cfg,
		mutator:                mutator,
		scanner:                NewInitialStateScanner(),
		matcher:                matcher,
		logger:                 logger,
		ctxInfo:                ctxInfo,
		metrics:                metrics,
		podStateCache:          podStateCache,
		stateWriter:            stateWriter,
		eligibleDeployments:    eligible,
		instrumentationManager: NewInstrumentationManager(cfg),
		nodeName:               nodeName,
		uuid:                   uuid.NewString(),
		stateCfg:               &stateCfg,
		stateHash:              stateHash,
	}

	s.lastEligiblePodLaunchNS.Store(now.UnixNano())
	s.externalWebhookUpdateNS.Store(now.UnixNano())
	s.initialPodScan.Store(true)

	return s, nil
}

// Start starts the webhook coordinator
func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("starting communication to Injection controller")

	if err := s.instrumentationManager.checkImageVolumeSupport(s.ctxInfo.K8sInformer); err != nil {
		return err
	}

	if s.podStateCache != nil {
		go s.subscribeStateCache(ctx)
	}

	if s.stateWriter != nil {
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

	<-ctx.Done()
	s.logger.Debug("shutting down webhook coordinator")
	// Don't return ctx.Err() as an error - graceful shutdown is expected
	if errors.Is(ctx.Err(), context.Canceled) {
		return nil
	}
	return ctx.Err()
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
	return s.setOrUpdateInitialProcessState()
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
	if s.stateWriter == nil {
		return
	}

	s.eligibleDeploymentsMux.Lock()
	defer s.eligibleDeploymentsMux.Unlock()

	key := deploymentKeyFromProcess(a)
	d := deploymentFromProcess(a, s.stateHash)

	if !d.Valid() {
		s.logger.Debug("invalid deployment", "key", key, "deployment", d)
		return
	}

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

	return s.stateWriter.Write(ctx, s.stateCfg, eligible)
}

func sortEligible(eligible []*configmap.EligibleDeployment) {
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].Namespace != eligible[j].Namespace {
			return eligible[i].Namespace < eligible[j].Namespace
		}
		return eligible[i].Name < eligible[j].Name
	})
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

	if s.handleExternalWebhookEvent(event) {
		return nil
	}

	if !s.isMyNodeEvent(event) {
		return nil
	}

	if event.Type != informer.EventType_CREATED && event.Type != informer.EventType_UPDATED {
		return nil
	}

	if err := s.loadProcessStateIfNecessary(); err != nil {
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

func (s *Server) loadProcessStateIfNecessary() error {
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
	// It's important to check here for the SDK supported programming languages.
	// Go would be the killer here, since many of the Kubernetes services are written in
	// Go, and we don't want to say bounce coredns.
	if !s.mutator.CanInstrument(a) || s.mutator.PreloadsSomethingElse(a) {
		s.logger.Debug("ignoring process because of unsupported programming language or LD_PRELOAD", "info", a)
		return
	}

	// The match process info only relies on the initial process state
	// so it will not find any info on new processes. This is by design, since
	// we don't want to do work for processes we've seen after we've launched,
	// they'll get seen by the webhook when the pods start, before there's info.
	if _, matched := s.matcher.MatchProcessInfo(a); matched {
		s.recordEligibleDeployment(a)
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

func mutationKey(namespace, deploymentName string) string {
	return trimmedName(namespace) + "/" + trimmedName(deploymentName)
}

func trimmedName(name string) string {
	return strings.TrimSpace(name)
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
					// handleNewProcessEvent will request a config map
					// update if any changes are needed
					s.handleNewProcessEvent(a)
				}
			}
		}
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
