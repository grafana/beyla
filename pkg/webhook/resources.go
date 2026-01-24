package webhook

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/distribution/reference"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

func (pm *PodMutator) setResourceAttributes(meta *metav1.ObjectMeta, container *corev1.Container) {

	// entries from the CRD have the lowest precedence - they are overridden by later values
	cfg := pm.cfg.Injector.Resources

	// Extra resource attributes that don't have dedicated OTEL_INJECTOR_* variables
	extraResAttrs := map[attribute.Key]string{}
	for k, v := range cfg.Attributes {
		extraResAttrs[attribute.Key(k)] = v
	}

	setEnvVar(container, envInjectorOtelK8sContainerName, container.Name)

	pm.addParentResourceLabels(meta, extraResAttrs, cfg.AddK8sUIDAttributes)

	// Set K8s attributes from downwards API
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

	// todo: propagators and sampler from config?
	//idx = getIndexOfEnv(container.Env, constants.EnvOTELPropagators)
	//if idx == -1 && len(otelinst.Spec.Propagators) > 0 {
	//	propagators := *(*[]string)((unsafe.Pointer(&otelinst.Spec.Propagators)))
	//	container.Env = append(container.Env, corev1.EnvVar{
	//		Name:  constants.EnvOTELPropagators,
	//		Value: strings.Join(propagators, ","),
	//	})
	//}
	//
	//idx = getIndexOfEnv(container.Env, constants.EnvOTELTracesSampler)
	//// configure sampler only if it is configured in the CR
	//if idx == -1 && otelinst.Spec.Sampler.Type != "" {
	//	idxSamplerArg := getIndexOfEnv(container.Env, constants.EnvOTELTracesSamplerArg)
	//	if idxSamplerArg == -1 {
	//		container.Env = append(container.Env, corev1.EnvVar{
	//			Name:  constants.EnvOTELTracesSampler,
	//			Value: string(otelinst.Spec.Sampler.Type),
	//		})
	//		if otelinst.Spec.Sampler.Argument != "" {
	//			container.Env = append(container.Env, corev1.EnvVar{
	//				Name:  constants.EnvOTELTracesSamplerArg,
	//				Value: otelinst.Spec.Sampler.Argument,
	//			})
	//		}
	//	}
	//}

	if pm.cfg.Metrics.Features.AnySpanMetrics() {
		extraResAttrs[attr.SkipSpanMetrics.OTEL()] = "true"
	}

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

var cannotRetrieveImage = errors.New("cannot retrieve image name")

// parseServiceVersionFromImage parses the service version for differently-formatted image names
// according to https://github.com/open-telemetry/semantic-conventions/blob/main/docs/non-normative/k8s-attributes.md#how-serviceversion-should-be-calculated
func parseServiceVersionFromImage(image string) (string, error) {
	ref, err := reference.Parse(image)
	if err != nil {
		return "", err
	}

	namedRef, ok := ref.(reference.Named)
	if !ok {
		return "", cannotRetrieveImage
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

	return "", cannotRetrieveImage
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
		serviceInstanceId = strings.Join(resNames, ".")
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
	for _, owner := range meta.OwnerReferences {
		switch strings.ToLower(owner.Kind) {
		case "replicaset":
			resources[semconv.K8SReplicaSetNameKey] = owner.Name
			if includeUID {
				resources[semconv.K8SReplicaSetUIDKey] = string(owner.UID)
			}
			// parent of ReplicaSet is e.g. Deployment which we are interested to know
			// todo
			//rs := appsv1.ReplicaSet{}
			//nsn := types.NamespacedName{Namespace: ns.Name, Name: owner.Name}
			//backOff := wait.Backoff{Duration: 10 * time.Millisecond, Factor: 1.5, Jitter: 0.1, Steps: 20, Cap: 2 * time.Second}
			//
			//checkError := func(err error) bool {
			//	return apierrors.IsNotFound(err)
			//}
			//
			//getReplicaSet := func() error {
			//	return i.client.Get(ctx, nsn, &rs)
			//}
			//
			//// use a retry loop to get the Deployment. A single call to client.get fails occasionally
			//err := retry.OnError(backOff, checkError, getReplicaSet)
			//if err != nil {
			//	i.logger.Error(err, "failed to get replicaset", "replicaset", nsn.Name, "namespace", nsn.Namespace)
			//}
			//i.addParentResourceLabels(ctx, uid, ns, rs.ObjectMeta, resources)
		case "deployment":
			resources[semconv.K8SDeploymentNameKey] = owner.Name
			if includeUID {
				resources[semconv.K8SDeploymentUIDKey] = string(owner.UID)
			}
		case "statefulset":
			resources[semconv.K8SStatefulSetNameKey] = owner.Name
			if includeUID {
				resources[semconv.K8SStatefulSetUIDKey] = string(owner.UID)
			}
		case "daemonset":
			resources[semconv.K8SDaemonSetNameKey] = owner.Name
			if includeUID {
				resources[semconv.K8SDaemonSetUIDKey] = string(owner.UID)
			}
		case "job":
			resources[semconv.K8SJobNameKey] = owner.Name
			if includeUID {
				resources[semconv.K8SJobUIDKey] = string(owner.UID)
			}

			// parent of Job can be CronJob which we are interested to know
			// todo
			//j := batchv1.Job{}
			//nsn := types.NamespacedName{Namespace: ns.Name, Name: owner.Name}
			//backOff := wait.Backoff{Duration: 10 * time.Millisecond, Factor: 1.5, Jitter: 0.1, Steps: 20, Cap: 2 * time.Second}
			//
			//checkError := func(err error) bool {
			//	return apierrors.IsNotFound(err)
			//}
			//
			//getJob := func() error {
			//	return i.client.Get(ctx, nsn, &j)
			//}
			//
			//// use a retry loop to get the Job. A single call to client.get fails occasionally
			//err := retry.OnError(backOff, checkError, getJob)
			//if err != nil {
			//	i.logger.Error(err, "failed to get job", "job", nsn.Name, "namespace", nsn.Namespace)
			//}
			//i.addParentResourceLabels(ctx, uid, ns, j.ObjectMeta, resources)
		case "cronjob":
			resources[semconv.K8SCronJobNameKey] = owner.Name
			if includeUID {
				resources[semconv.K8SCronJobUIDKey] = string(owner.UID)
			}
		}
	}
}
