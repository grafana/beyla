// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package selection // import "go.opentelemetry.io/obi/pkg/selection"

import "context"

// K8sWorkloadRef identifies a Kubernetes workload by kind, namespace, and name.
// Kind values match informer owner kinds. Dynamic selection currently accepts top-level
// controllers only (Deployment, StatefulSet, DaemonSet, CronJob); see discover.ParseK8sWorkload.
type K8sWorkloadRef struct {
	Kind      string
	Namespace string
	Name      string
}

// K8sWorkloadSelector is implemented by dynamic selector views that track Kubernetes
// workloads in addition to PIDs. DynamicAppIPs uses this for network/stats-only selection.
type K8sWorkloadSelector interface {
	GetK8sWorkloads() []K8sWorkloadRef
	// WorkloadsChangedNotifyContext wakes when the selected workload set changes. Callers
	// that need the current set should call GetK8sWorkloads.
	WorkloadsChangedNotifyContext(context.Context) <-chan struct{}
}
