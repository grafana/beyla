// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
)

type indexableEntity struct {
	// the informers library requires to embed this field
	metav1.ObjectMeta
	// the protobuf-encoded object Metadata that will be actually sent over the wire
	EncodedMeta *informer.ObjectMeta
}

// ownerFrom returns the owner references, as well as the owners from the owners. It might be
// null if the entity does not have any owner
func ownersFrom(meta *metav1.ObjectMeta) []*informer.Owner {
	if len(meta.OwnerReferences) == 0 {
		// If no owner references' found, return itself as owner
		return []*informer.Owner{{Kind: typePod, Name: meta.Name}}
	}
	owners := make([]*informer.Owner, 0, len(meta.OwnerReferences))
	for i := range meta.OwnerReferences {
		or := &meta.OwnerReferences[i]
		owners = append(owners, &informer.Owner{Kind: or.Kind, Name: or.Name})
		// ReplicaSets usually have a Deployment as owner too. Returning it as well
		if or.APIVersion == "apps/v1" && or.Kind == "ReplicaSet" {
			// we heuristically extract the Deployment name from the replicaset name
			if idx := strings.LastIndexByte(or.Name, '-'); idx > 0 {
				owners = append(owners, &informer.Owner{Kind: "Deployment", Name: or.Name[:idx]})
				// we already have what we need for decoration and selection. Ignoring any other owner
				// it might hypothetically have (it would be a rare case)
				return owners
			}
		}
		if or.APIVersion == "batch/v1" && or.Kind == "Job" {
			// we heuristically extract the CronJob name from the Job name
			if idx := strings.LastIndexByte(or.Name, '-'); idx > 0 {
				owners = append(owners, &informer.Owner{Kind: "CronJob", Name: or.Name[:idx]})
				// we already have what we need for decoration and selection. Ignoring any other owner
				// it might hypothetically have (it would be a rare case)
				return owners
			}
		}
	}
	return owners
}
