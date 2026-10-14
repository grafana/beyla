// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"errors"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/selection"
)

type workloadKey struct {
	kind      string
	namespace string
	name      string
}

func (k workloadKey) ref() selection.K8sWorkloadRef {
	return selection.K8sWorkloadRef{Kind: k.kind, Namespace: k.namespace, Name: k.name}
}

func workloadKeyFromRef(ref selection.K8sWorkloadRef) workloadKey {
	return workloadKey{kind: ref.Kind, namespace: ref.Namespace, name: ref.Name}
}

// ParseK8sWorkload extracts a workload identity from a typed Kubernetes object pointer or
// selection.K8sWorkloadRef. Supported types: *Deployment, *StatefulSet, *DaemonSet,
// *CronJob, and K8sWorkloadRef with those kinds.
func ParseK8sWorkload(obj any) (selection.K8sWorkloadRef, error) {
	if obj == nil {
		return selection.K8sWorkloadRef{}, errors.New("k8s workload is nil")
	}

	switch o := obj.(type) {
	case selection.K8sWorkloadRef:
		return validateWorkloadRef(o)
	case *selection.K8sWorkloadRef:
		if o == nil {
			return selection.K8sWorkloadRef{}, errors.New("k8s workload is nil")
		}
		return validateWorkloadRef(*o)

	case *appsv1.Deployment:
		if o == nil {
			return selection.K8sWorkloadRef{}, errors.New("k8s workload is nil")
		}
		return refFromMeta("Deployment", o)
	case *appsv1.StatefulSet:
		if o == nil {
			return selection.K8sWorkloadRef{}, errors.New("k8s workload is nil")
		}
		return refFromMeta("StatefulSet", o)
	case *appsv1.DaemonSet:
		if o == nil {
			return selection.K8sWorkloadRef{}, errors.New("k8s workload is nil")
		}
		return refFromMeta("DaemonSet", o)

	case *batchv1.CronJob:
		if o == nil {
			return selection.K8sWorkloadRef{}, errors.New("k8s workload is nil")
		}
		return refFromMeta("CronJob", o)

	default:
		return selection.K8sWorkloadRef{}, fmt.Errorf("unsupported k8s workload type %T", obj)
	}
}

type objectMetaAccessor interface {
	GetName() string
	GetNamespace() string
}

func refFromMeta(kind string, obj objectMetaAccessor) (selection.K8sWorkloadRef, error) {
	return validateWorkloadRef(selection.K8sWorkloadRef{
		Kind:      kind,
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
	})
}

func validateWorkloadRef(ref selection.K8sWorkloadRef) (selection.K8sWorkloadRef, error) {
	if ref.Kind == "" {
		return selection.K8sWorkloadRef{}, errors.New("k8s workload kind is required")
	}
	if ref.Name == "" {
		return selection.K8sWorkloadRef{}, errors.New("k8s workload name is required")
	}
	if ref.Namespace == "" {
		return selection.K8sWorkloadRef{}, errors.New("k8s workload namespace is required")
	}
	if metadataAttrForKind(ref.Kind) == "" {
		return selection.K8sWorkloadRef{}, fmt.Errorf("unsupported k8s workload kind %q", ref.Kind)
	}
	return ref, nil
}

// metadataAttrForKind returns the process-metadata attribute used to match a selected workload.
//
// Only top-level controllers are supported today: Deployment, StatefulSet, DaemonSet, CronJob.
//
// TODO: ReplicaSet, Job, and Pod selection may be added later. Holding off because overlapping
// selections raise unresolved questions about attribute precedence and inheritance (whose
// DynamicOptions win when a process matches multiple identities), and that policy looks more
// like a config surface than something to hard-code in the selector.
func metadataAttrForKind(kind string) string {
	switch kind {
	case "Deployment":
		return services.AttrDeploymentName
	case "StatefulSet":
		return services.AttrStatefulSetName
	case "DaemonSet":
		return services.AttrDaemonSetName
	case "CronJob":
		return services.AttrCronJobName
	default:
		return ""
	}
}

func workloadMatchesMetadata(key workloadKey, meta map[string]string) bool {
	if meta == nil {
		return false
	}
	if meta[services.AttrNamespace] != key.namespace {
		return false
	}
	attrName := metadataAttrForKind(key.kind)
	if attrName == "" {
		return false
	}
	return meta[attrName] == key.name
}
