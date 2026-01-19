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
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
	runtimeScheme = runtime.NewScheme()
	codecFactory  = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecFactory.UniversalDeserializer()
)

const (
	injectVolumeName   = "otel-inject-instrumentation"
	initContainerName  = "otel-inject-instrumentation"
	injectVolumeSizeMB = 500
	injectorImage      = "ghcr.io/grafana/beyla/inject-sdk-image:0.0.1"
	// this value is hardcoded in the copy script and the injector config
	internalMountPath = "/__otel_sdk_auto_instrumentation__"

	envVarLdPreloadName             = "LD_PRELOAD"
	envVarLdPreloadValue            = internalMountPath + "/injector/libotelinject.so"
	envOtelInjectorConfigFileName   = "OTEL_INJECTOR_CONFIG_FILE"
	envOtelInjectorConfigFileValue  = internalMountPath + "/injector/otelinject.conf"
	envOtelExporterOtlpEndpointName = "OTEL_EXPORTER_OTLP_ENDPOINT"
)

func init() {
	_ = corev1.AddToScheme(runtimeScheme)
	_ = admissionv1.AddToScheme(runtimeScheme)
}

// PodMutator handles the mutation of pods
type PodMutator struct {
	logger *slog.Logger
}

// NewPodMutator creates a new PodMutator
func NewPodMutator() *PodMutator {
	return &PodMutator{
		logger: slog.Default().With("component", "webhook"),
	}
}

func errorResponse(admResponse *admissionv1.AdmissionResponse, message string) {
	admResponse.Allowed = false
	admResponse.Result = &metav1.Status{
		Message: message,
	}
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
						admResponse.Allowed = false
						errorResponse(admResponse, "no changes")
					}
				}
			} else {
				pm.logger.Info("no mutations needed", "pod", pod.Name, "namespace", pod.Namespace)
			}
		}
	}

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

// TODO: Add some labels to make sure we mark this pod as something we've instrumented
// TODO: How do we detect that we caused the pod to crash and not do this again on restart?
func (pm *PodMutator) mutatePod(pod *corev1.Pod) bool {
	spec := &pod.Spec

	// check if maybe someone is adding instrumentation manually
	if pm.alreadyInstrumented(spec) {
		return false
	}

	originalSpec := spec.DeepCopy()

	// mount the volume with the injector and SDKs
	pm.mountVolume(spec, &pod.ObjectMeta)
	// create the init container to copy all the files over to the mounted volume
	pm.addInitContainer(spec)

	// instrument all containers that don't have some preexisting LD_PRELOAD set on them
	for _, c := range spec.Containers {
		if _, ok := findEnvVar(&c, envVarLdPreloadName); ok {
			pm.logger.Warn("container already using LD_PRELOAD, ignoring...", "container", c.Name)
			continue
		}
		pm.instrumentContainer(&c)
	}

	return !reflect.DeepEqual(originalSpec, spec)
}

// TODO: we also need to check perhaps for labels set by the OTel operator and skip
// those containers too
func (pm *PodMutator) alreadyInstrumented(spec *corev1.PodSpec) bool {
	for _, c := range spec.Containers {
		if _, ok := findEnvVar(&c, envOtelInjectorConfigFileName); ok {
			pm.logger.Debug("container already instrumented, ignoring...", "container", c.Name)
			return true
		}
	}

	return false
}

func (pm *PodMutator) mountVolume(spec *corev1.PodSpec, meta *metav1.ObjectMeta) {
	if spec.Volumes == nil {
		spec.Volumes = make([]corev1.Volume, 0)
	}

	v := corev1.Volume{
		Name: injectVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{
				// Enough space for all the instrumentations and future
				// SDKs that are not currently supported.
				SizeLimit: resource.NewScaledQuantity(injectVolumeSizeMB, resource.Mega),
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

	// we need to set this new volume as safe to evict, to avoid not allowing
	// nodes to be scaled down. This volume contains only disposable data.
	if meta.Annotations == nil {
		meta.Annotations = make(map[string]string)
	}

	const safeToEvict = "cluster-autoscaler.kubernetes.io/safe-to-evict-local-volumes"

	annotation, ok := meta.Annotations[safeToEvict]

	if !ok {
		meta.Annotations[safeToEvict] = injectVolumeName
		return
	}

	if !strings.Contains(annotation, injectVolumeName) {
		volumes := volumes(annotation)
		volumes = append(volumes, injectVolumeName)
		meta.Annotations[safeToEvict] = strings.Join(volumes, ",")
		return
	}

}

func volumes(annotationValue string) []string {
	result := []string{}

	for _, v := range strings.Split(annotationValue, ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		result = append(result, v)
	}
	return result
}

func (pm *PodMutator) addInitContainer(podSpec *corev1.PodSpec) {
	if podSpec.InitContainers == nil {
		podSpec.InitContainers = make([]corev1.Container, 0)
	}
	pos := slices.IndexFunc(podSpec.InitContainers, func(c corev1.Container) bool {
		return c.Name == initContainerName
	})

	initContainer := pm.createInitContainer(podSpec)
	if pos < 0 {
		podSpec.InitContainers = append(podSpec.InitContainers, *initContainer)
	} else {
		podSpec.InitContainers[pos] = *initContainer
	}
}

func (pm *PodMutator) createInitContainer(podSpec *corev1.PodSpec) *corev1.Container {
	nonSystemUserGroup := int64(10_000)
	privileged := false
	allowEscalate := false
	readOnlyFS := true

	initContainerUser := &nonSystemUserGroup
	initContainerGroup := &nonSystemUserGroup

	securityContext := podSpec.SecurityContext
	if securityContext == nil {
		securityContext = &corev1.PodSecurityContext{}
	}
	if securityContext.FSGroup != nil {
		initContainerUser = securityContext.FSGroup
		initContainerGroup = securityContext.FSGroup
	}

	initContainer := &corev1.Container{
		Name:  initContainerName,
		Image: injectorImage,
		SecurityContext: &corev1.SecurityContext{
			Privileged:               &privileged,
			AllowPrivilegeEscalation: &allowEscalate,
			ReadOnlyRootFilesystem:   &readOnlyFS,
			RunAsNonRoot:             securityContext.RunAsNonRoot,
			RunAsUser:                initContainerUser,
			RunAsGroup:               initContainerGroup,
			SeccompProfile: &corev1.SeccompProfile{
				Type: corev1.SeccompProfileTypeRuntimeDefault,
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      injectVolumeName,
				ReadOnly:  false,
				MountPath: internalMountPath,
			},
		},
		ImagePullPolicy: "IfNotPresent", // TODO: needs config
	}

	return initContainer
}

func (pm *PodMutator) instrumentContainer(c *corev1.Container) {
	pm.addMount(c)
	pm.addEnvironmentVariables(c)
}

func (pm *PodMutator) addMount(container *corev1.Container) {
	if container.VolumeMounts == nil {
		container.VolumeMounts = make([]corev1.VolumeMount, 0)
	}
	idx := slices.IndexFunc(container.VolumeMounts, func(c corev1.VolumeMount) bool {
		return c.Name == injectVolumeName
	})

	volume := &corev1.VolumeMount{
		Name:      injectVolumeName,
		MountPath: internalMountPath,
	}
	if idx < 0 {
		container.VolumeMounts = append(container.VolumeMounts, *volume)
	} else {
		container.VolumeMounts[idx] = *volume
	}
}

func findEnvVar(c *corev1.Container, name string) (int, bool) {
	pos := slices.IndexFunc(c.Env, func(c corev1.EnvVar) bool {
		return c.Name == name
	})

	return pos, pos >= 0
}

func setEnvVar(c *corev1.Container, envVar corev1.EnvVar) {
	if pos, ok := findEnvVar(c, envVar.Name); !ok {
		c.Env = append(c.Env, envVar)
	} else {
		c.Env[pos].ValueFrom = nil
		c.Env[pos].Value = envVar.Value
	}
}

func (pm *PodMutator) addEnvironmentVariables(c *corev1.Container) {
	if c.Env == nil {
		c.Env = []corev1.EnvVar{}
	}

	setEnvVar(c,
		corev1.EnvVar{
			Name:  envVarLdPreloadName,
			Value: envVarLdPreloadValue,
		},
	)

	setEnvVar(c,
		corev1.EnvVar{
			Name:  envOtelInjectorConfigFileName,
			Value: envOtelInjectorConfigFileValue,
		},
	)

	// TODO: Add exporter variables, resource attributes, etc.
}

// HealthCheck is a simple health check endpoint
func (pm *PodMutator) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
