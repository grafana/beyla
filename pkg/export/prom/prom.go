package prom

import (
	"strings"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// injectable function reference for testing
var timeNow = time.Now

// using labels and names that are equivalent names to the OTEL attributes
// but following the different naming conventions
const (
	serviceNameKey      = "service_name"
	serviceNamespaceKey = "service_namespace"

	hostIDKey   = "host_id"
	hostNameKey = "host_name"
	osTypeKey   = "os_type"

	k8sNamespaceName   = "k8s_namespace_name"
	k8sPodName         = "k8s_pod_name"
	k8sContainerName   = "k8s_container_name"
	k8sDeploymentName  = "k8s_deployment_name"
	k8sStatefulSetName = "k8s_statefulset_name"
	k8sReplicaSetName  = "k8s_replicaset_name"
	k8sDaemonSetName   = "k8s_daemonset_name"
	k8sJobName         = "k8s_job_name"
	k8sCronJobName     = "k8s_cronjob_name"
	k8sNodeName        = "k8s_node_name"
	k8sPodUID          = "k8s_pod_uid"
	k8sPodStartTime    = "k8s_pod_start_time"
	k8sClusterName     = "k8s_cluster_name"
	k8sKind            = "k8s_kind"
	k8sOwnerName       = "k8s_owner_name"

	serviceInstanceKey   = "instance"
	serviceJobKey        = "job"
	sourceKey            = "source"
	telemetryLanguageKey = "telemetry_sdk_language"
	telemetrySDKKey      = "telemetry_sdk_name"
)

func parseExtraMetadata(labels []string) []attr.Name {
	// first, we convert any metric in snake_format to dotted.format,
	// as it is the internal representation of metadata labels
	attrNames := make([]attr.Name, len(labels))
	for i, label := range labels {
		attrNames[i] = attr.Name(strings.ReplaceAll(label, "_", "."))
	}
	return attrNames
}

func appendK8sLabelNames(names []string) []string {
	names = append(names, k8sNamespaceName, k8sPodName, k8sContainerName, k8sNodeName, k8sPodUID, k8sPodStartTime,
		k8sDeploymentName, k8sReplicaSetName, k8sStatefulSetName, k8sJobName, k8sCronJobName, k8sDaemonSetName, k8sClusterName, k8sKind, k8sOwnerName)
	return names
}

func appendK8sLabelValuesService(values []string, service *svc.Attrs) []string {
	// must follow the order in appendK8sLabelNames
	values = append(values,
		service.Metadata[attr.K8sNamespaceName],
		service.Metadata[attr.K8sPodName],
		service.Metadata[attr.K8sContainerName],
		service.Metadata[attr.K8sNodeName],
		service.Metadata[attr.K8sPodUID],
		service.Metadata[attr.K8sPodStartTime],
		service.Metadata[attr.K8sDeploymentName],
		service.Metadata[attr.K8sReplicaSetName],
		service.Metadata[attr.K8sStatefulSetName],
		service.Metadata[attr.K8sJobName],
		service.Metadata[attr.K8sCronJobName],
		service.Metadata[attr.K8sDaemonSetName],
		service.Metadata[attr.K8sClusterName],
		service.Metadata[attr.K8sKind],
		service.Metadata[attr.K8sOwnerName],
	)
	return values
}

func labelNamesTargetInfo(kubeEnabled bool, extraMetadataLabelNames []attr.Name) []string {
	names := []string{
		hostIDKey,
		hostNameKey,
		serviceNameKey,
		serviceNamespaceKey,
		serviceInstanceKey,
		serviceJobKey,
		telemetryLanguageKey,
		telemetrySDKKey,
		sourceKey,
		osTypeKey,
	}

	if kubeEnabled {
		names = appendK8sLabelNames(names)
	}

	for _, mdn := range extraMetadataLabelNames {
		names = append(names, mdn.Prom())
	}

	return names
}

func labelNames[T any](getters []attributes.Field[T, string]) []string {
	labels := make([]string, 0, len(getters))
	for _, label := range getters {
		labels = append(labels, label.ExposedName)
	}
	return labels
}

func labelValues[T any](s T, getters []attributes.Field[T, string]) []string {
	values := make([]string, 0, len(getters))
	for _, getter := range getters {
		values = append(values, getter.Get(s))
	}
	return values
}
