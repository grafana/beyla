// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

// TopOwner assumes that the owners slice as returned by the informers' cache library,
// is sorted from lower-level to upper-level, so the last owner will be the top owner
// (e.g. the Deployment that owns the ReplicaSet that owns a Pod).
func TopOwner(pod *informer.PodInfo) *informer.Owner {
	if pod == nil || len(pod.Owners) == 0 {
		return nil
	}
	return pod.Owners[len(pod.Owners)-1]
}

// CachedObjMeta is a wrapper around the informer.ObjectMeta that also contains
// the OTEL resource metadata.
type CachedObjMeta struct {
	Meta             *informer.ObjectMeta
	OTELResourceMeta map[attr.Name]string
}
