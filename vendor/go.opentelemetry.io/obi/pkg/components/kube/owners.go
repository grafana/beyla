// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kube

import (
	"go.opentelemetry.io/obi/pkg/kubecache/informer"
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
