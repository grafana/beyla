package webhook

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/distribution/reference"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

const (
	ResourceAttributeAnnotationPrefix = "resource.opentelemetry.io/"
)

var (
	LabelAppName = []string{
		"app.kubernetes.io/instance",
		"app.kubernetes.io/name",
	}
	LabelAppVersion = []string{"app.kubernetes.io/version"}
)

// configureContainerEnvVars sets all environment variables for the container including
// resource attributes, sampler configuration, and service identification.
// nolint:gocritic
func (pm *PodMutator) configureContainerEnvVars(meta *metav1.ObjectMeta, container *corev1.Container, selector services.Selector) {
	extraResAttrs := pm.setResourceAttributes(meta, container)

	// Configure propagators from default config
	if len(pm.cfg.Injector.Propagators) > 0 {
		pm.configurePropagators(container, pm.cfg.Injector.Propagators)
	}

	// Configure sampler with priority: selector > default
	var samplerConfig *services.SamplerConfig
	if selector != nil {
		samplerConfig = selector.GetSamplerConfig()
	}
	if samplerConfig == nil {
		samplerConfig = pm.cfg.Injector.DefaultSampler
	}
	if samplerConfig != nil {
		pm.configureSampler(container, samplerConfig)
	}

	if pm.cfg.Metrics.Features.AnySpanMetrics() {
		extraResAttrs[attr.SkipSpanMetrics.OTEL()] = "true"
	}

	pm.injectEnvVars(extraResAttrs, container)
}

func (pm *PodMutator) injectEnvVars(extraResAttrs map[attribute.Key]string, container *corev1.Container) {
	// Set extra resource attributes if any exist
	if len(extraResAttrs) > 0 {
		var resourceAttributeList []string
		for _, resourceAttributeKey := range slices.Sorted(maps.Keys(extraResAttrs)) {
			resourceAttributeList = append(
				resourceAttributeList,
				fmt.Sprintf("%s=%s", resourceAttributeKey, extraResAttrs[resourceAttributeKey]))
		}
		setEnvVar(container, envInjectorOtelExtraResourceAttrs, strings.Join(resourceAttributeList, ","))
	}
}

func (pm *PodMutator) setResourceAttributes(meta *metav1.ObjectMeta, container *corev1.Container) map[attribute.Key]string {
	cfg := pm.cfg.Injector.Resources

	// entries from the CRD have the lowest precedence - they are overridden by later values
	extraResAttrs := map[attribute.Key]string{}
	for k, v := range cfg.Attributes {
		extraResAttrs[attribute.Key(k)] = v
	}

	setEnvVar(container, envInjectorOtelK8sContainerName, container.Name)

	pm.addParentResourceLabels(meta, extraResAttrs, cfg.AddK8sUIDAttributes)

	namespace := setEnvVarFromFieldPath(container, envInjectorOtelK8sNamespaceName, "metadata.namespace")
	podName := setEnvVarFromFieldPath(container, envInjectorOtelK8sPodName, "metadata.name")
	// node name has to be added to extra attributes as there is no dedicated OTEL_INJECTOR_* variable
	extraResAttrs[semconv.K8SNodeNameKey] =
		setEnvVarFromFieldPath(container, envOtelK8sNodeName, "spec.nodeName")

	if cfg.AddK8sUIDAttributes {
		setEnvVarFromFieldPath(container, envInjectorOtelK8sPodUID, "metadata.uid")
	}

	// Set service attributes using dedicated env vars
	setEnvVar(container, envInjectorOtelServiceNamespace, chooseServiceNamespace(meta, cfg.UseLabelsForResourceAttributes, namespace))
	setEnvVar(container, envInjectorOtelServiceName, chooseServiceName(meta, cfg.UseLabelsForResourceAttributes, podName, extraResAttrs))
	setEnvVar(container, envInjectorOtelServiceVersion, chooseServiceVersion(meta, cfg.UseLabelsForResourceAttributes, container))

	// Service instance ID is added to extra attributes since it uses pod name reference
	serviceInstanceId := createServiceInstanceId(meta, namespace, podName, container.Name)
	if serviceInstanceId != "" {
		extraResAttrs[semconv.ServiceInstanceIDKey] = serviceInstanceId
	}

	// attributes from the pod annotations have the highest precedence
	for k, v := range meta.GetAnnotations() {
		if strings.HasPrefix(k, ResourceAttributeAnnotationPrefix) {
			extraResAttrs[attribute.Key(strings.TrimPrefix(k, ResourceAttributeAnnotationPrefix))] = v
		}
	}
	return extraResAttrs
}

// configureSampler sets sampler environment variables from the provided sampler configuration.
// The samplerConfig parameter must be non-nil.
// Respects existing environment variables (won't override user settings).
func (pm *PodMutator) configureSampler(container *corev1.Container, samplerConfig *services.SamplerConfig) {
	// Use existing setEnvVar helper (handles empty values and duplicates)
	setEnvVar(container, envOtelTracesSamplerName, samplerConfig.Name)
	setEnvVar(container, envOtelTracesSamplerArgName, samplerConfig.Arg)
}

// configurePropagators sets propagators environment variable from the provided list.
// The propagators parameter must be non-empty.
// Respects existing environment variables (won't override user settings).
func (pm *PodMutator) configurePropagators(container *corev1.Container, propagators []string) {
	// Join propagators with comma separator as per OTEL spec
	setEnvVar(container, envOtelPropagatorsName, strings.Join(propagators, ","))
}

// chooseServiceName returns the service name to be used in the instrumentation.
// See https://github.com/open-telemetry/semantic-conventions/blob/main/docs/non-normative/k8s-attributes.md#how-servicename-should-be-calculated
func chooseServiceName(meta *metav1.ObjectMeta, useLabelsForResourceAttributes bool, podName string, resources map[attribute.Key]string) string {
	if name := chooseLabelOrAnnotation(meta, useLabelsForResourceAttributes, semconv.ServiceNameKey, LabelAppName); name != "" {
		return name
	}
	if name := resources[semconv.K8SDeploymentNameKey]; name != "" {
		return name
	}
	if name := resources[semconv.K8SReplicaSetNameKey]; name != "" {
		return name
	}
	if name := resources[semconv.K8SStatefulSetNameKey]; name != "" {
		return name
	}
	if name := resources[semconv.K8SDaemonSetNameKey]; name != "" {
		return name
	}
	if name := resources[semconv.K8SCronJobNameKey]; name != "" {
		return name
	}
	if name := resources[semconv.K8SJobNameKey]; name != "" {
		return name
	}
	return podName
}

// chooseLabelOrAnnotation returns the value of the label or annotation with the given key.
// The precedence is as follows:
// 1. annotation with key resource.opentelemetry.io/<resource>.
// 2. label with key labelKey.
func chooseLabelOrAnnotation(meta *metav1.ObjectMeta, useLabelsForResourceAttributes bool, resource attribute.Key, labelKeys []string) string {
	if v := meta.GetAnnotations()[(ResourceAttributeAnnotationPrefix + string(resource))]; v != "" {
		return v
	}
	if useLabelsForResourceAttributes {
		for _, labelKey := range labelKeys {
			if v := meta.GetLabels()[labelKey]; v != "" {
				return v
			}
		}
	}
	return ""
}

// chooseServiceVersion returns the service version to be used in the instrumentation.
// See https://github.com/open-telemetry/semantic-conventions/blob/main/docs/non-normative/k8s-attributes.md#how-serviceversion-should-be-calculated
func chooseServiceVersion(meta *metav1.ObjectMeta, useLabelsForResourceAttributes bool, container *corev1.Container) string {
	v := chooseLabelOrAnnotation(meta, useLabelsForResourceAttributes, semconv.ServiceVersionKey, LabelAppVersion)
	if v != "" {
		return v
	}
	var err error
	v, err = parseServiceVersionFromImage(container.Image)
	if err != nil {
		return ""
	}
	return v
}

// chooseServiceNamespace returns the service.namespace to be used in the instrumentation.
// See https://github.com/open-telemetry/semantic-conventions/blob/main/docs/non-normative/k8s-attributes.md#how-servicenamespace-should-be-calculated
func chooseServiceNamespace(meta *metav1.ObjectMeta, useLabelsForResourceAttributes bool, namespaceName string) string {
	namespace := chooseLabelOrAnnotation(meta, useLabelsForResourceAttributes, semconv.ServiceNamespaceKey, nil)
	if namespace != "" {
		return namespace
	}
	return namespaceName
}

var errCannotRetrieveImage = errors.New("cannot retrieve image name")

// parseServiceVersionFromImage parses the service version for differently-formatted image names
// according to https://github.com/open-telemetry/semantic-conventions/blob/main/docs/non-normative/k8s-attributes.md#how-serviceversion-should-be-calculated
func parseServiceVersionFromImage(image string) (string, error) {
	ref, err := reference.Parse(image)
	if err != nil {
		return "", err
	}

	namedRef, ok := ref.(reference.Named)
	if !ok {
		return "", errCannotRetrieveImage
	}
	var tag, digest string
	if taggedRef, ok := namedRef.(reference.Tagged); ok {
		tag = taggedRef.Tag()
	}
	if digestedRef, ok := namedRef.(reference.Digested); ok {
		digest = digestedRef.Digest().String()
	}
	if digest != "" {
		if tag != "" {
			return fmt.Sprintf("%s@%s", tag, digest), nil
		}
		return digest, nil
	}
	if tag != "" {
		return tag, nil
	}

	return "", errCannotRetrieveImage
}

// chooseServiceInstanceId returns the service.instance.id to be used in the instrumentation.
// See https://github.com/open-telemetry/semantic-conventions/blob/main/docs/non-normative/k8s-attributes.md#how-serviceinstanceid-should-be-calculated
func createServiceInstanceId(meta *metav1.ObjectMeta, namespaceName, podName, containerName string) string {
	// Do not use labels for service instance id,
	// because multiple containers in the same pod would get the same service instance id,
	// which violates the uniqueness requirement of service instance id -
	// see https://opentelemetry.io/docs/specs/semconv/resource/#service-experimental.
	// We still allow the user to set the service instance id via annotation, because this is explicitly set by the user.
	serviceInstanceId := chooseLabelOrAnnotation(meta, false, semconv.ServiceInstanceIDKey, nil)
	if serviceInstanceId != "" {
		return serviceInstanceId
	}

	if namespaceName != "" && podName != "" && containerName != "" {
		resNames := []string{namespaceName, podName, containerName}
		return strings.Join(resNames, ".")
	}
	return ""
}

// setEnvVarFromFieldPath is a helper function that sets an environment variable from a Kubernetes downwards API field path
func setEnvVarFromFieldPath(container *corev1.Container, envVarName, fieldPath string) string {
	container.Env = append(container.Env, corev1.EnvVar{
		Name: envVarName,
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{
				FieldPath: fieldPath,
			},
		},
	})
	return fmt.Sprintf("$(%s)", envVarName)
}

func (pm *PodMutator) addParentResourceLabels(meta *metav1.ObjectMeta, resources map[attribute.Key]string, includeUID bool) {
	for _, owner := range ownersFrom(meta) {
		resourceAttribute := getResourceAttribute(owner.Kind)
		if resourceAttribute != "" {
			resources[resourceAttribute] = owner.Name
		}
	}
	if includeUID {
		for _, owner := range meta.OwnerReferences {
			resourceAttribute := getResourceAttribute(owner.Kind)
			if resourceAttribute != "" {
				resources[resourceAttribute] = string(owner.UID)
			}
		}
	}
}

func getResourceAttribute(kind string) attribute.Key {
	switch strings.ToLower(kind) {
	case "replicaset":
		return semconv.K8SReplicaSetNameKey
	case "deployment":
		return semconv.K8SDeploymentNameKey
	case "statefulset":
		return semconv.K8SStatefulSetNameKey
	case "daemonset":
		return semconv.K8SDaemonSetNameKey
	case "job":
		return semconv.K8SJobNameKey
	case "cronjob":
		return semconv.K8SCronJobNameKey
	default:
		return ""
	}
}
