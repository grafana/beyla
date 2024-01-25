package kube

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOwnerString(t *testing.T) {
	owner := Owner{Type: OwnerReplicaSet, Name: "rs"}
	assert.Equal(t, "k8s.replicaset.name:rs", owner.String())
	owner.Owner = &Owner{Type: OwnerDeployment, Name: "dep"}
	assert.Equal(t, "k8s.deployment.name:dep->k8s.replicaset.name:rs", owner.String())
}
