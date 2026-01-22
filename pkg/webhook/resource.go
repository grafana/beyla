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
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"
	corev1 "k8s.io/api/core/v1"
)

const (
	EnvPodUID  = "OTEL_RESOURCE_ATTRIBUTES_POD_UID"
	EnvPodName = "OTEL_RESOURCE_ATTRIBUTES_POD_NAME"

	ResourceAttributeAnnotationPrefix = "resource.opentelemetry.io/"
)

var (
	LabelAppName = []string{
		"app.kubernetes.io/instance",
		"app.kubernetes.io/name",
	}
	LabelAppVersion = []string{"app.kubernetes.io/version"}
)

func (pm *PodMutator) setResourceAttributes(container *corev1.Container, pod *corev1.Pod) {

	// entries from the CRD have the lowest precedence - they are overridden by later values
	cfg := pm.cfg.Injector.Webhook.Resource

	res := map[string]string{}
	for k, v := range cfg.Attributes {
		res[k] = v
	}

	// k8s resources have a higher precedence than CRD entries
	k8sResources := map[attribute.Key]string{}
	k8sResources[semconv.K8SNamespaceNameKey] = pod.Namespace
	k8sResources[semconv.K8SContainerNameKey] = container.Name
	// Some fields might be empty - node name, pod name
	// The pod name might be empty if the pod is created form deployment template
	k8sResources[semconv.K8SPodUIDKey] = string(pod.UID)
	k8sResources[semconv.K8SNodeNameKey] = pod.Spec.NodeName
	k8sResources[semconv.ServiceInstanceIDKey] = createServiceInstanceId(pod, pod.Namespace, downwardsAPIRef(EnvPodName), container.Name)
	// todo do we already have this info cached?
	//pm.addParentResourceLabels(ctx, cfg.AddK8sUIDAttributes, ns, pod.ObjectMeta, k8sResources)

	for k, v := range k8sResources {
		if v != "" {
			res[string(k)] = v
		}
	}

	// attributes and labels from the pod have the highest precedence (except for values set in environment variables)
	for k, v := range pod.GetAnnotations() {
		if strings.HasPrefix(k, ResourceAttributeAnnotationPrefix) {
			key := strings.TrimPrefix(k, ResourceAttributeAnnotationPrefix)
			if key != string(semconv.ServiceNameKey) {
				res[key] = v
			}
		}
	}

	namespace := chooseServiceNamespace(pod, cfg.UseLabelsForResourceAttributes, pod.Namespace)
	if namespace != "" {
		res[string(semconv.ServiceNamespaceKey)] = namespace
	}

	res[string(semconv.ServiceNameKey)] = chooseServiceName(pod, cfg.UseLabelsForResourceAttributes, res, container)

	addFromDownwardsAPI(container, res, semconv.K8SPodNameKey, EnvPodName, "metadata.name")

	// Some attributes might be empty, we should get them via k8s downward API
	if cfg.AddK8sUIDAttributes {
		addFromDownwardsAPI(container, res, semconv.K8SPodUIDKey, EnvPodUID, "metadata.uid")
	}

	vsn := chooseServiceVersion(pod, cfg.UseLabelsForResourceAttributes, container)
	if vsn != "" {
		res[string(semconv.ServiceVersionKey)] = vsn
	}

	addFromDownwardsAPI(container, res, semconv.K8SNodeNameKey, "OTEL_RESOURCE_ATTRIBUTES_NODE_NAME", "spec.nodeName")

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
		res[string(attr.SkipSpanMetrics.OTEL())] = "true"
	}

	if len(res) > 0 {
		var resourceAttributeList []string
		for _, resourceAttributeKey := range slices.Sorted(maps.Keys(res)) {
			resourceAttributeList = append(
				resourceAttributeList,
				fmt.Sprintf("%s=%s", resourceAttributeKey, res[resourceAttributeKey]))
		}
		setEnvVar(container,
			corev1.EnvVar{
				Name:  envOtelExtraResourceAttrs,
				Value: strings.Join(resourceAttributeList, ","),
			})
	}
}

func addFromDownwardsAPI(container *corev1.Container, res map[string]string, key attribute.Key, envVar string, fieldPath string) {
	if res[string(key)] == "" {
		container.Env = append(container.Env, corev1.EnvVar{
			Name: envVar,
			ValueFrom: &corev1.EnvVarSource{
				FieldRef: &corev1.ObjectFieldSelector{
					FieldPath: fieldPath,
				},
			},
		})
		res[string(key)] = downwardsAPIRef(envVar)
	}
}

func downwardsAPIRef(envVar string) string {
	return fmt.Sprintf("$(%s)", envVar)
}

// chooseServiceName returns the service name to be used in the instrumentation.
// See https://github.com/open-telemetry/semantic-conventions/blob/main/docs/non-normative/k8s-attributes.md#how-servicename-should-be-calculated
func chooseServiceName(pod *corev1.Pod, useLabelsForResourceAttributes bool, resources map[string]string, container *corev1.Container) string {
	if name := chooseLabelOrAnnotation(pod, useLabelsForResourceAttributes, semconv.ServiceNameKey, LabelAppName); name != "" {
		return name
	}
	if name := resources[string(semconv.K8SDeploymentNameKey)]; name != "" {
		return name
	}
	if name := resources[string(semconv.K8SReplicaSetNameKey)]; name != "" {
		return name
	}
	if name := resources[string(semconv.K8SStatefulSetNameKey)]; name != "" {
		return name
	}
	if name := resources[string(semconv.K8SDaemonSetNameKey)]; name != "" {
		return name
	}
	if name := resources[string(semconv.K8SCronJobNameKey)]; name != "" {
		return name
	}
	if name := resources[string(semconv.K8SJobNameKey)]; name != "" {
		return name
	}
	if name := resources[string(semconv.K8SPodNameKey)]; name != "" {
		return name
	}
	return container.Name
}

// chooseLabelOrAnnotation returns the value of the label or annotation with the given key.
// The precedence is as follows:
// 1. annotation with key resource.opentelemetry.io/<resource>.
// 2. label with key labelKey.
func chooseLabelOrAnnotation(pod *corev1.Pod, useLabelsForResourceAttributes bool, resource attribute.Key, labelKeys []string) string {
	if v := pod.GetAnnotations()[(ResourceAttributeAnnotationPrefix + string(resource))]; v != "" {
		return v
	}
	if useLabelsForResourceAttributes {
		for _, labelKey := range labelKeys {
			if v := pod.GetLabels()[labelKey]; v != "" {
				return v
			}
		}
	}
	return ""
}

// chooseServiceVersion returns the service version to be used in the instrumentation.
// See https://github.com/open-telemetry/semantic-conventions/blob/main/docs/non-normative/k8s-attributes.md#how-serviceversion-should-be-calculated
func chooseServiceVersion(pod *corev1.Pod, useLabelsForResourceAttributes bool, container *corev1.Container) string {
	v := chooseLabelOrAnnotation(pod, useLabelsForResourceAttributes, semconv.ServiceVersionKey, LabelAppVersion)
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
func chooseServiceNamespace(pod *corev1.Pod, useLabelsForResourceAttributes bool, namespaceName string) string {
	namespace := chooseLabelOrAnnotation(pod, useLabelsForResourceAttributes, semconv.ServiceNamespaceKey, nil)
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
func createServiceInstanceId(pod *corev1.Pod, namespaceName, podName, containerName string) string {
	// Do not use labels for service instance id,
	// because multiple containers in the same pod would get the same service instance id,
	// which violates the uniqueness requirement of service instance id -
	// see https://opentelemetry.io/docs/specs/semconv/resource/#service-experimental.
	// We still allow the user to set the service instance id via annotation, because this is explicitly set by the user.
	serviceInstanceId := chooseLabelOrAnnotation(pod, false, semconv.ServiceInstanceIDKey, nil)
	if serviceInstanceId != "" {
		return serviceInstanceId
	}

	if namespaceName != "" && podName != "" && containerName != "" {
		resNames := []string{namespaceName, podName, containerName}
		serviceInstanceId = strings.Join(resNames, ".")
	}
	return serviceInstanceId
}

//func (pm *PodMutator) addParentResourceLabels(ctx context.Context, uid bool, ns corev1.Namespace, objectMeta metav1.ObjectMeta, resources map[attribute.Key]string) {
//	for _, owner := range objectMeta.OwnerReferences {
//		switch strings.ToLower(owner.Kind) {
//		case "replicaset":
//			resources[semconv.K8SReplicaSetNameKey] = owner.Name
//			if uid {
//				resources[semconv.K8SReplicaSetUIDKey] = string(owner.UID)
//			}
//			// parent of ReplicaSet is e.g. Deployment which we are interested to know
//			rs := appsv1.ReplicaSet{}
//			nsn := types.NamespacedName{Namespace: ns.Name, Name: owner.Name}
//			backOff := wait.Backoff{Duration: 10 * time.Millisecond, Factor: 1.5, Jitter: 0.1, Steps: 20, Cap: 2 * time.Second}
//
//			checkError := func(err error) bool {
//				return apierrors.IsNotFound(err)
//			}
//
//			getReplicaSet := func() error {
//				return i.client.Get(ctx, nsn, &rs)
//			}
//
//			// use a retry loop to get the Deployment. A single call to client.get fails occasionally
//			err := retry.OnError(backOff, checkError, getReplicaSet)
//			if err != nil {
//				i.logger.Error(err, "failed to get replicaset", "replicaset", nsn.Name, "namespace", nsn.Namespace)
//			}
//			i.addParentResourceLabels(ctx, uid, ns, rs.ObjectMeta, resources)
//		case "deployment":
//			resources[semconv.K8SDeploymentNameKey] = owner.Name
//			if uid {
//				resources[semconv.K8SDeploymentUIDKey] = string(owner.UID)
//			}
//		case "statefulset":
//			resources[semconv.K8SStatefulSetNameKey] = owner.Name
//			if uid {
//				resources[semconv.K8SStatefulSetUIDKey] = string(owner.UID)
//			}
//		case "daemonset":
//			resources[semconv.K8SDaemonSetNameKey] = owner.Name
//			if uid {
//				resources[semconv.K8SDaemonSetUIDKey] = string(owner.UID)
//			}
//		case "job":
//			resources[semconv.K8SJobNameKey] = owner.Name
//			if uid {
//				resources[semconv.K8SJobUIDKey] = string(owner.UID)
//			}
//
//			// parent of Job can be CronJob which we are interested to know
//			j := batchv1.Job{}
//			nsn := types.NamespacedName{Namespace: ns.Name, Name: owner.Name}
//			backOff := wait.Backoff{Duration: 10 * time.Millisecond, Factor: 1.5, Jitter: 0.1, Steps: 20, Cap: 2 * time.Second}
//
//			checkError := func(err error) bool {
//				return apierrors.IsNotFound(err)
//			}
//
//			getJob := func() error {
//				return i.client.Get(ctx, nsn, &j)
//			}
//
//			// use a retry loop to get the Job. A single call to client.get fails occasionally
//			err := retry.OnError(backOff, checkError, getJob)
//			if err != nil {
//				i.logger.Error(err, "failed to get job", "job", nsn.Name, "namespace", nsn.Namespace)
//			}
//			i.addParentResourceLabels(ctx, uid, ns, j.ObjectMeta, resources)
//		case "cronjob":
//			resources[semconv.K8SCronJobNameKey] = owner.Name
//			if uid {
//				resources[semconv.K8SCronJobUIDKey] = string(owner.UID)
//			}
//		}
//	}
//}
