package webhook

import (
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/transform"

	"github.com/grafana/beyla/v3/pkg/beyla"
	"github.com/grafana/beyla/v3/pkg/webhook/configmap"
)

var (
	runtimeScheme = runtime.NewScheme()
)

const (
	instrumentedLabel = "com.grafana.beyla/instrumented"
	injectVolumeName  = "otel-inject-instrumentation"
	// this value is hardcoded in the config file
	internalMountPath = "/__otel_sdk_auto_instrumentation__"

	envVarLdPreloadName            = "LD_PRELOAD"
	envVarLdPreloadValue           = internalMountPath + "/dist/injector/libotelinject.so"
	envOtelInjectorConfigFileName  = "OTEL_INJECTOR_CONFIG_FILE"
	envOtelInjectorConfigFileValue = internalMountPath + "/dist/injector/otelinject.conf"
	envVarSDKVersion               = "BEYLA_INJECTOR_SDK_PKG_VERSION"
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
	metrics *SDKInjectionMetrics

	endpoint      string
	proto         string
	exportHeaders map[string]string
}

// Endpoint returns the OTLP endpoint the mutator stamps onto matched pods.
// Exposed so the state ConfigMap writer can advertise the same destination to
// the external injection controller.
func (pm *PodMutator) Endpoint() string { return pm.endpoint }

// Protocol returns the OTLP protocol string ("http/protobuf", "grpc", ...).
func (pm *PodMutator) Protocol() string { return pm.proto }

// NewPodMutator creates a new PodMutator
// TODO: we don't need most of the code, as this is already mutated in the external webhook. Cleanup
func NewPodMutator(cfg *beyla.Config, matcher *PodMatcher, metrics *SDKInjectionMetrics) (*PodMutator, error) {
	var opts otelcfg.OTLPOptions

	protocol, endpoint, err := protoEndpoint(cfg)
	if err != nil {
		return nil, err
	}

	logger := slog.Default().With("component", "webhook")

	return &PodMutator{
		logger:        logger,
		matcher:       matcher,
		cfg:           cfg,
		metrics:       metrics,
		endpoint:      endpoint,
		exportHeaders: opts.Headers,
		proto:         string(protocol),
	}, nil
}

// protoEnpoint returns the most likely endpoint from the Beyla configuration.
// Known issue 1: there are some edge cases, like Beyla defining only a traces exporter
// but configuring the injector to export only metrics. In this case, Beyla would
// anyway silently assign the Traces OTLP endpoint to the SDK injector.
// Known issue 2: Beyla might configure different endpoints for both metrics and traces,
// but would pass only the traces endpoint to the injected SDK, to submit all the signals.
func protoEndpoint(cfg *beyla.Config) (otelcfg.Protocol, string, error) {
	// check if the injector has been supplied an endpoint and protocol and if not,
	// then we pull out the endpoint and the protocol from Beyla's configuration.
	protocol := cfg.Injector.Protocol
	endpoint := cfg.Injector.Endpoint

	// If the SDK injector is configured to export traces, try first to get the traces endpoint
	if endpoint == "" && cfg.Injector.ExportedSignals.TracesEnabled() {
		protocol = cfg.Traces.GetProtocol()
		var common bool
		endpoint, common = cfg.Traces.OTLPTracesEndpoint()
		if !common {
			endpoint = strings.TrimSuffix(endpoint, "/v1/traces")
		}
	}

	// fallback to the metrics endpoint
	if endpoint == "" {
		protocol = cfg.OTELMetrics.GetProtocol()
		var common bool
		if endpoint, common = cfg.OTELMetrics.OTLPMetricsEndpoint(); !common {
			endpoint = strings.TrimSuffix(endpoint, "/v1/metrics")
		}
	}

	// edge case: Beyla is working in Prometheus-only mode and
	// the user defines an inject section without an OTEL endpoint
	if endpoint == "" {
		return "", "", errors.New("working with OTEL SDK injection requires defining an OTLP endpoint")
	}

	if protocol == "" {
		protocol = otelcfg.ProtocolHTTPProtobuf
	}

	return protocol, endpoint, nil
}

func errorResponse(admResponse *admissionv1.AdmissionResponse, message string) {
	admResponse.Allowed = false
	admResponse.Result = &metav1.Status{
		Message: message,
	}
}

func (pm *PodMutator) CanInstrument(info *ProcessInfo) bool {
	for _, k := range pm.cfg.Injector.EnabledSDKs {
		if k.InstrumentableType == info.kind {
			return !info.incompatible
		}
	}
	return false
}

func (pm *PodMutator) CanInstrumentLanguage(kind svc.InstrumentableType) bool {
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
		return label == pm.cfg.Injector.PackageVersion()
	}

	// this a duplicate of the check above, but done on environment variables
	if ver, ok := info.env[envVarSDKVersion]; ok && ver != "" {
		return ver == pm.cfg.Injector.PackageVersion()
	}

	return false
}

func (pm *PodMutator) buildVolumeDefinition() corev1.Volume {
	return corev1.Volume{
		Name: injectVolumeName,
		VolumeSource: corev1.VolumeSource{
			Image: &corev1.ImageVolumeSource{
				Reference:  pm.cfg.Injector.ImageVersion,
				PullPolicy: corev1.PullIfNotPresent,
			},
		},
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

// isLDPreloadConflict returns true only when LD_PRELOAD is set to a non-empty
// value that is not Beyla's own injector path. An empty LD_PRELOAD or one
// already set to our value is not a conflict.
func isLDPreloadConflict(c *corev1.Container) bool {
	pos, ok := findEnvVar(c, envVarLdPreloadName)
	if !ok {
		return false
	}
	val := c.Env[pos].Value
	return val != "" && val != envVarLdPreloadValue
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

	// ownerChain carries the resolved owners (e.g. ReplicaSet → Deployment) so
	// OwnerName/OwnerKind selectors can match any link. ownersFrom returns
	// {Kind: "Pod"} for bare pods; skip it so a standalone pod has an empty chain.
	for _, owner := range owners {
		ret.metadata[transform.OwnerLabelName(owner.Kind).Prom()] = owner.Name
		if owner.Kind != "Pod" {
			ret.ownerChain = append(ret.ownerChain, configmap.Owner{Name: owner.Name, Kind: owner.Kind})
		}
	}
	return &ret
}

// HealthCheck is a simple health check endpoint
func (pm *PodMutator) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		pm.logger.Debug("error responding to health check", "error", err)
	}
}

// languageLabel converts an InstrumentableType to the Prometheus label string
// used in SDK injection metrics. Returns "" for unknown or generic types.
func languageLabel(kind svc.InstrumentableType) string {
	switch kind {
	case svc.InstrumentableUnknown, svc.InstrumentableGeneric:
		return ""
	default:
		return kind.String()
	}
}

// detectLanguageFromPodSpec returns the best-guess language for a pod by
// scanning each container's image name and command/args. Returns "" when
// the language cannot be determined from the available pod spec signals.
func detectLanguageFromPodSpec(pod *corev1.Pod) string {
	for i := range pod.Spec.Containers {
		if lang := detectLanguageFromContainer(&pod.Spec.Containers[i]); lang != "" {
			return lang
		}
	}
	return ""
}

func detectLanguageFromContainer(c *corev1.Container) string {
	if lang := languageFromImageName(c.Image); lang != "" {
		return lang
	}
	for _, token := range append(c.Command, c.Args...) {
		// strip directory prefix so "/usr/bin/python3" matches as "python3"
		if idx := strings.LastIndex(token, "/"); idx >= 0 {
			token = token[idx+1:]
		}
		if lang := languageFromToken(strings.ToLower(token)); lang != "" {
			return lang
		}
	}
	return ""
}

// languageFromImageName matches well-known image names to a language.
// It strips the digest and tag before matching, but keeps the full registry
// path so that images like mcr.microsoft.com/dotnet/aspnet are detected.
func languageFromImageName(image string) string {
	lower := strings.ToLower(image)
	if idx := strings.Index(lower, "@"); idx >= 0 {
		lower = lower[:idx]
	}
	// strip tag only when the colon has no slash after it (avoids cutting registry ports)
	if idx := strings.LastIndex(lower, ":"); idx >= 0 && !strings.Contains(lower[idx:], "/") {
		lower = lower[:idx]
	}
	// extract the image name component for short-word matching
	name := lower
	if idx := strings.LastIndex(lower, "/"); idx >= 0 {
		name = lower[idx+1:]
	}
	return languageFromToken(name)
}

// languageFromToken matches a single lowercase token (image name component,
// command basename, or arg) to a language string.
func languageFromToken(s string) string {
	switch {
	case strings.Contains(s, "dotnet") || strings.Contains(s, "aspnet"):
		return svc.InstrumentableDotnet.String()
	case strings.Contains(s, "python"):
		return svc.InstrumentablePython.String()
	case strings.Contains(s, "nodejs"):
		return svc.InstrumentableNodejs.String()
	case s == "node":
		return svc.InstrumentableNodejs.String()
	case strings.Contains(s, "java") || strings.Contains(s, "jdk") ||
		strings.Contains(s, "jre") || strings.Contains(s, "corretto") ||
		strings.Contains(s, "temurin"):
		return svc.InstrumentableJava.String()
	}
	return ""
}
