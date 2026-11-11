// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes // import "go.opentelemetry.io/obi/pkg/export/attributes"

import attr "go.opentelemetry.io/obi/pkg/export/attributes/names"

func KubernetesTargetInfoAttributes() []attr.Name {
	return []attr.Name{
		attr.K8sNamespaceName,
		attr.K8sPodName,
		attr.K8sContainerName,
		attr.K8sNodeName,
		attr.K8sPodUID,
		attr.K8sPodStartTime,
		attr.K8sDeploymentName,
		attr.K8sReplicaSetName,
		attr.K8sStatefulSetName,
		attr.K8sJobName,
		attr.K8sCronJobName,
		attr.K8sDaemonSetName,
		attr.K8sClusterName,
		attr.K8sKind,
		attr.K8sOwnerName,
	}
}
