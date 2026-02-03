package webhook

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/transform"

	"github.com/grafana/beyla/v2/pkg/beyla"
)

var (
	runtimeScheme     = runtime.NewScheme()
	codecFactory      = serializer.NewCodecFactory(runtimeScheme)
	deserializer      = codecFactory.UniversalDeserializer()
	supportedSDKLangs = []svc.InstrumentableType{svc.InstrumentableDotnet, svc.InstrumentableJava, svc.InstrumentableNodejs}
)

const (
	instrumentedLabel = "com.grafana.beyla/instrumented"
	injectVolumeName  = "otel-inject-instrumentation"
	// this value is hardcoded in the config file
	internalMountPath = "/__otel_sdk_auto_instrumentation__"

	envVarLdPreloadName               = "LD_PRELOAD"
	envVarLdPreloadValue              = internalMountPath + "/injector/libotelinject.so"
	envOtelInjectorConfigFileName     = "OTEL_INJECTOR_CONFIG_FILE"
	envOtelInjectorConfigFileValue    = internalMountPath + "/injector/otelinject.conf"
	envOtelExporterOtlpEndpointName   = "OTEL_EXPORTER_OTLP_ENDPOINT"
	envOtelExporterOtlpProtocolName   = "OTEL_EXPORTER_OTLP_PROTOCOL"
	envOtelSemConvStabilityName       = "OTEL_SEMCONV_STABILITY_OPT_IN"
	envInjectorOtelExtraResourceAttrs = "OTEL_INJECTOR_RESOURCE_ATTRIBUTES"
	envInjectorOtelServiceName        = "OTEL_INJECTOR_SERVICE_NAME"
	envInjectorOtelServiceVersion     = "OTEL_INJECTOR_SERVICE_VERSION"
	envInjectorOtelServiceNamespace   = "OTEL_INJECTOR_SERVICE_NAMESPACE"
	envInjectorOtelK8sNamespaceName   = "OTEL_INJECTOR_K8S_NAMESPACE_NAME"
	envInjectorOtelK8sPodName         = "OTEL_INJECTOR_K8S_POD_NAME"
	envInjectorOtelK8sPodUID          = "OTEL_INJECTOR_K8S_POD_UID"
	envInjectorOtelK8sContainerName   = "OTEL_INJECTOR_K8S_CONTAINER_NAME"
	envOtelK8sNodeName                = "OTEL_RESOURCE_ATTRIBUTES_NODE_NAME" // stored in OTEL_INJECTOR_RESOURCE_ATTRIBUTES, since there's no individual OTEL_INJECTOR_K8S_NODE_NAME
	envVarSDKVersion                  = "BEYLA_INJECTOR_SDK_PKG_VERSION"
	envOtelTracesSamplerName          = "OTEL_TRACES_SAMPLER"
	envOtelTracesSamplerArgName       = "OTEL_TRACES_SAMPLER_ARG"
	envOtelPropagatorsName            = "OTEL_PROPAGATORS"
	envOtelMetricsExporterName        = "OTEL_METRICS_EXPORTER"
	envOtelTracesExporterName         = "OTEL_TRACES_EXPORTER"
	envOtelLogsExporterName           = "OTEL_LOGS_EXPORTER"

	// Enabling/disabling of language specific SDKs
	envDotnetEnabledName = "DOTNET_AUTO_INSTRUMENTATION_AGENT_PATH_PREFIX"
	envJavaEnabledName   = "JVM_AUTO_INSTRUMENTATION_AGENT_PATH"
	envNodejsEnabledName = "NODEJS_AUTO_INSTRUMENTATION_AGENT_PATH"
)

func init() {
	_ = corev1.AddToScheme(runtimeScheme)
	_ = admissionv1.AddToScheme(runtimeScheme)
}

// PodMutator handles the mutation of pods
type PodMutator struct {
	logger  *slog.Logger
	matcher *PodMatcher
	cfg     *beyla.Config

	endpoint      string
	proto         string
	exportHeaders map[string]string
}

// NewPodMutator creates a new PodMutator
func NewPodMutator(cfg *beyla.Config, matcher *PodMatcher) (*PodMutator, error) {
	var opts otelcfg.OTLPOptions
	var err error

	switch proto := cfg.Traces.GetProtocol(); proto {
	case otelcfg.ProtocolHTTPJSON, otelcfg.ProtocolHTTPProtobuf, "":
		opts, err = otelcfg.HTTPTracesEndpointOptions(&cfg.Traces)
		if err != nil {
			return nil, err
		}
	case otelcfg.ProtocolGRPC:
		opts, err = otelcfg.GRPCTracesEndpointOptions(&cfg.Traces)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported SDK export protocol %s", proto)
	}

	logger := slog.Default().With("component", "webhook")
	return &PodMutator{
		logger:        logger,
		matcher:       matcher,
		cfg:           cfg,
		endpoint:      opts.Scheme + "://" + opts.Endpoint + opts.BaseURLPath,
		exportHeaders: opts.Headers,
		proto:         string(cfg.Traces.Protocol),
	}, nil
}

func errorResponse(admResponse *admissionv1.AdmissionResponse, message string) {
	admResponse.Allowed = false
	admResponse.Result = &metav1.Status{
		Message: message,
	}
}

func (pm *PodMutator) CanInstrument(kind svc.InstrumentableType) bool {
	for _, k := range pm.cfg.Injector.EnabledSDKs {
		if k.InstrumentableType == kind {
			return true
		}
	}
	return false
}

func (pm *PodMutator) PreloadsSomethingElse(info *ProcessInfo) bool {
	// If there's an LD_PRELOAD on this process, don't touch it if it's not us
	if injector, ok := info.env[envVarLdPreloadName]; ok {
		if injector != envVarLdPreloadValue {
			return true
		}
	}
	return false
}

func (pm *PodMutator) AlreadyInstrumented(info *ProcessInfo) bool {
	// Consult the labels, if we instrumented the pod, we'd have set the
	// instrumented label.
	if label, ok := info.podLabels[instrumentedLabel]; ok && label != "" {
		return label == pm.cfg.Injector.SDKPkgVersion
	}

	// this a duplicate of the check above, but done on environment variables
	if ver, ok := info.env[envVarSDKVersion]; ok && ver != "" {
		return ver == pm.cfg.Injector.SDKPkgVersion
	}

	return false
}

// HandleMutate is the HTTP handler for the mutating webhook
func (pm *PodMutator) HandleMutate(w http.ResponseWriter, r *http.Request) {
	pm.logger.Info("received mutation request", "remoteAddr", r.RemoteAddr)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		pm.logger.Error("failed to read request body", "error", err)
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Verify the content type
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		pm.logger.Error("invalid content type", "contentType", contentType)
		http.Error(w, "invalid Content-Type, expect application/json", http.StatusUnsupportedMediaType)
		return
	}

	// Decode the admission review request
	admReview := admissionv1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &admReview); err != nil {
		pm.logger.Error("failed to decode admission review", "error", err)
		http.Error(w, fmt.Sprintf("failed to decode admission review: %v", err), http.StatusBadRequest)
		return
	}

	if admReview.Request == nil {
		pm.logger.Error("admission review request is nil")
		http.Error(w, "admission review request is nil", http.StatusBadRequest)
		return
	}

	pm.logger.Info("processing admission request", "uid", admReview.Request.UID, "kind", admReview.Request.Kind.Kind)

	// Create the admission response
	admResponse := &admissionv1.AdmissionResponse{
		UID:     admReview.Request.UID,
		Allowed: true,
	}

	// add a label with the version of the SDKs we've instrumented
	if pm.cfg.Injector.SDKPkgVersion == "" {
		errorResponse(admResponse, "SDK package version must be set")
		pm.mutateResponse(w, admResponse)
		return
	}

	// Process the pod
	if admReview.Request.Kind.Kind == "Pod" {
		pod := corev1.Pod{}
		if err := json.Unmarshal(admReview.Request.Object.Raw, &pod); err != nil {
			pm.logger.Error("failed to unmarshal pod", "error", err)
			errorResponse(admResponse, fmt.Sprintf("failed to unmarshal pod: %v", err))
		} else {
			pm.logger.Info("mutating pod", "name", pod.Name, "namespace", pod.Namespace)
			// Generate patches for the pod
			if modified := pm.mutatePod(&pod); modified {
				marshalled, err := json.Marshal(pod)
				if err != nil {
					pm.logger.Error("failed to marshall modified pod", "error", err, "pod", pod.Name, "namespace", pod.Namespace)
					errorResponse(admResponse, fmt.Sprintf("failed to marshall modified pod: %v", err))
				} else {
					// Debug: log sizes to understand what's being compared
					pm.logger.Info("generating patch", "originalSize", len(admReview.Request.Object.Raw), "modifiedSize", len(marshalled))

					// Create admission.Request from the raw admission request
					patchResponse := admission.PatchResponseFromRaw(admReview.Request.Object.Raw, marshalled)

					if len(patchResponse.Patches) > 0 {
						patchBytes, err := json.Marshal(patchResponse.Patches)
						if err != nil {
							pm.logger.Error("failed to marshal patches", "error", err)
							errorResponse(admResponse, fmt.Sprintf("failed to marshal patches: %v", err))
						} else {
							pm.logger.Info("mutating pod", "pod", pod.Name, "namespace", pod.Namespace, "patches", patchResponse.Patches)
							admResponse.Patch = patchBytes
							patchType := admissionv1.PatchTypeJSONPatch
							admResponse.PatchType = &patchType
						}
					} else {
						errorResponse(admResponse, "no changes")
					}
				}
			} else {
				pm.logger.Info("no mutations needed", "pod", pod.Name, "namespace", pod.Namespace)
			}
		}
	}

	pm.mutateResponse(w, admResponse)
}

func (pm *PodMutator) mutateResponse(w http.ResponseWriter, admResponse *admissionv1.AdmissionResponse) {
	// Construct the response
	admReviewResponse := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Response: admResponse,
	}

	respBytes, err := json.Marshal(admReviewResponse)
	if err != nil {
		pm.logger.Error("failed to marshal response", "error", err)
		http.Error(w, fmt.Sprintf("failed to marshal response: %v", err), http.StatusInternalServerError)
		return
	}

	pm.logger.Info("sending admission response", "uid", admResponse.UID, "allowed", admResponse.Allowed, "responseSize", len(respBytes))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(respBytes); err != nil {
		pm.logger.Error("failed to write response", "error", err)
		return
	}

	pm.logger.Info("admission response sent successfully", "uid", admResponse.UID)
}

func (pm *PodMutator) mutatePod(pod *corev1.Pod) bool {
	spec := &pod.Spec
	meta := &pod.ObjectMeta

	// check if maybe someone is adding instrumentation manually
	if pm.alreadyInstrumented(spec, meta) {
		return false
	}

	selector, matched := pm.matchesSelection(meta)
	if !matched {
		pm.logger.Info("pod doesn't match selection criteria")
		return false
	}

	originalSpec := spec.DeepCopy()

	// mount the shared hostPath volume with the injector and SDKs
	pm.mountVolume(spec, meta)

	// instrument all containers that don't have some preexisting LD_PRELOAD set on them
	for i := range spec.Containers {
		c := &spec.Containers[i]
		if _, ok := findEnvVar(c, envVarLdPreloadName); ok {
			pm.logger.Warn("container already using LD_PRELOAD, ignoring...", "container", c.Name)
			continue
		}
		pm.instrumentContainer(meta, c, selector)
	}

	pm.addLabel(meta, instrumentedLabel, pm.cfg.Injector.SDKPkgVersion)

	return !reflect.DeepEqual(originalSpec, spec)
}

func (pm *PodMutator) alreadyInstrumented(spec *corev1.PodSpec, meta *metav1.ObjectMeta) bool {
	for i := range spec.Containers {
		c := &spec.Containers[i]
		if _, ok := findEnvVar(c, envOtelInjectorConfigFileName); ok {
			pm.logger.Debug("container already instrumented, ignoring...", "container", c.Name)
			return true
		}
	}

	if val, ok := pm.getLabel(meta, instrumentedLabel); ok && val != "" {
		return true
	}

	return false
}

func (pm *PodMutator) mountVolume(spec *corev1.PodSpec, meta *metav1.ObjectMeta) {
	if spec.Volumes == nil {
		spec.Volumes = make([]corev1.Volume, 0)
	}

	// Use hostPath volume shared across all pods on the node
	// The Beyla DaemonSet deployment populates this directory once per node
	// and it must be setup before Beyla launches
	v := corev1.Volume{
		Name: injectVolumeName,
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{
				Path: strings.Join([]string{pm.cfg.Injector.HostPathVolumeDir, pm.cfg.Injector.SDKPkgVersion}, "/"),
				Type: func() *corev1.HostPathType {
					t := corev1.HostPathDirectoryOrCreate
					return &t
				}(),
			},
		},
	}

	pos := slices.IndexFunc(spec.Volumes, func(c corev1.Volume) bool {
		return c.Name == injectVolumeName
	})

	if pos < 0 {
		spec.Volumes = append(spec.Volumes, v)
	} else {
		spec.Volumes[pos] = v
	}
}

func (pm *PodMutator) instrumentContainer(meta *metav1.ObjectMeta, c *corev1.Container, selector services.Selector) {
	pm.addMount(c)
	pm.addEnvVars(meta, c, selector)
}

func (pm *PodMutator) addMount(c *corev1.Container) {
	if c.VolumeMounts == nil {
		c.VolumeMounts = make([]corev1.VolumeMount, 0)
	}
	idx := slices.IndexFunc(c.VolumeMounts, func(c corev1.VolumeMount) bool {
		return c.Name == injectVolumeName
	})

	volume := &corev1.VolumeMount{
		Name:      injectVolumeName,
		MountPath: internalMountPath,
	}
	if idx < 0 {
		c.VolumeMounts = append(c.VolumeMounts, *volume)
	} else {
		c.VolumeMounts[idx] = *volume
	}
}

func (pm *PodMutator) addLabel(meta *metav1.ObjectMeta, key string, value string) {
	if meta.Labels == nil {
		meta.Labels = make(map[string]string, 1)
	}
	meta.Labels[key] = value
}

func (pm *PodMutator) getLabel(meta *metav1.ObjectMeta, key string) (string, bool) {
	if meta.Labels == nil {
		return "", false
	}
	if value, ok := meta.Labels[key]; ok {
		return value, true
	}
	return "", false
}

func findEnvVar(c *corev1.Container, name string) (int, bool) {
	pos := slices.IndexFunc(c.Env, func(c corev1.EnvVar) bool {
		return c.Name == name
	})

	return pos, pos >= 0
}

// setEnvVar is a helper function that sets an environment variable only if the value is not empty
func setEnvVarEvenIfEmpty(c *corev1.Container, envVarName, value string) {
	if pos, ok := findEnvVar(c, envVarName); !ok {
		c.Env = append(c.Env, corev1.EnvVar{
			Name:  envVarName,
			Value: value,
		})
	} else {
		c.Env[pos].ValueFrom = nil
		c.Env[pos].Value = value
	}
}

// setEnvVar is a helper function that sets an environment variable only if the value is not empty
func setEnvVar(c *corev1.Container, envVarName, value string) {
	if value != "" {
		setEnvVarEvenIfEmpty(c, envVarName, value)
	}
}

func (pm *PodMutator) addEnvVars(meta *metav1.ObjectMeta, c *corev1.Container, selector services.Selector) {
	if c.Env == nil {
		c.Env = []corev1.EnvVar{}
	}

	// we set the SDK version on the environment variable so that
	// we can tell on start, when we scan the processes of the oldest
	// SDK version in use.
	setEnvVar(c, envVarSDKVersion, pm.cfg.Injector.SDKPkgVersion)
	setEnvVar(c, envVarLdPreloadName, envVarLdPreloadValue)
	setEnvVar(c, envOtelInjectorConfigFileName, envOtelInjectorConfigFileValue)
	setEnvVar(c, envOtelExporterOtlpEndpointName, pm.endpoint)
	setEnvVar(c, envOtelExporterOtlpProtocolName, pm.proto)
	setEnvVar(c, envOtelSemConvStabilityName, "http")

	pm.configureContainerEnvVars(meta, c, selector)
	pm.disableUndesiredSDKs(c)

	for k, v := range pm.exportHeaders {
		setEnvVar(c, k, v)
	}

	pm.logger.Info("env vars", "vars", c.Env)
}

func ownersFrom(meta *metav1.ObjectMeta) []*informer.Owner {
	if len(meta.OwnerReferences) == 0 {
		// If no owner references' found, return itself as owner
		return []*informer.Owner{{Kind: "Pod", Name: meta.Name}}
	}
	owners := make([]*informer.Owner, 0, len(meta.OwnerReferences))
	for i := range meta.OwnerReferences {
		or := &meta.OwnerReferences[i]
		owners = append(owners, &informer.Owner{Kind: or.Kind, Name: or.Name})
		// ReplicaSets usually have a Deployment as owner too. Returning it as well
		if or.APIVersion == "apps/v1" && or.Kind == "ReplicaSet" {
			// we heuristically extract the Deployment name from the replicaset name
			if idx := strings.LastIndexByte(or.Name, '-'); idx > 0 {
				owners = append(owners, &informer.Owner{Kind: "Deployment", Name: or.Name[:idx]})
				// we already have what we need for decoration and selection. Ignoring any other owner
				// it might hypothetically have (it would be a rare case)
				return owners
			}
		}
		if or.APIVersion == "batch/v1" && or.Kind == "Job" {
			// we heuristically extract the CronJob name from the Job name
			if idx := strings.LastIndexByte(or.Name, '-'); idx > 0 {
				owners = append(owners, &informer.Owner{Kind: "CronJob", Name: or.Name[:idx]})
				// we already have what we need for decoration and selection. Ignoring any other owner
				// it might hypothetically have (it would be a rare case)
				return owners
			}
		}
	}
	return owners
}

func processMetadata(meta *metav1.ObjectMeta) *ProcessInfo {
	ownerName := meta.Name
	owners := ownersFrom(meta)
	if topOwner := topOwner(owners); topOwner != nil {
		ownerName = topOwner.Name
	}

	ret := ProcessInfo{}

	ret.metadata = map[string]string{
		services.AttrNamespace: meta.Namespace,
		services.AttrPodName:   meta.Name,
		services.AttrOwnerName: ownerName,
	}
	ret.podLabels = meta.Labels
	ret.podAnnotations = meta.Annotations

	// add any other owner name (they might be several, e.g. replicaset and deployment)
	for _, owner := range owners {
		ret.metadata[transform.OwnerLabelName(owner.Kind).Prom()] = owner.Name
	}
	return &ret
}

func (pm *PodMutator) matchesSelection(meta *metav1.ObjectMeta) (services.Selector, bool) {
	info := processMetadata(meta)
	return pm.matcher.MatchProcessInfo(info)
}

// HealthCheck is a simple health check endpoint
func (pm *PodMutator) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		pm.logger.Debug("error responding to health check", "error", err)
	}
}
