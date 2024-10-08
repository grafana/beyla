package kube

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestOwnerString(t *testing.T) {
	owner := Owner{LabelName: OwnerReplicaSet, Name: "rs"}
	assert.Equal(t, "k8s.replicaset.name:rs", owner.String())
	owner.Owner = &Owner{LabelName: OwnerDeployment, Name: "dep"}
	assert.Equal(t, "k8s.deployment.name:dep->k8s.replicaset.name:rs", owner.String())
}

func TestOwnerFrom(t *testing.T) {
	for _, kind := range []string{"ReplicaSet", "Deployment", "StatefulSet", "DaemonSet"} {
		t.Run(kind, func(t *testing.T) {
			owner := OwnerFrom([]v1.OwnerReference{
				{APIVersion: "foo/bar", Kind: kind, Name: "no"},
				{APIVersion: "apps/v1", Kind: "Unknown", Name: "no"},
				{APIVersion: "apps/v1", Kind: kind, Name: "theowner"},
			})
			require.NotNil(t, owner)
			assert.Equal(t, &Owner{
				Kind:      kind,
				LabelName: OwnerLabel(fmt.Sprintf("k8s.%s.name", strings.ToLower(kind))),
				Name:      "theowner",
			}, owner)
		})
	}
}

func TestOwnerFrom_Unrecognized(t *testing.T) {
	owner := OwnerFrom([]v1.OwnerReference{
		{APIVersion: "foo/v1", Kind: "Unknown", Name: "theowner"},
	})
	require.NotNil(t, owner)
	assert.Equal(t, &Owner{
		LabelName: OwnerGeneric,
		Name:      "theowner",
	}, owner)
}

func TestOwnerFrom_Unrecognized_AppsV1(t *testing.T) {
	owner := OwnerFrom([]v1.OwnerReference{
		{APIVersion: "apps/v1", Kind: "Unknown", Name: "theowner"},
	})
	require.NotNil(t, owner)
	assert.Equal(t, &Owner{
		LabelName: OwnerGeneric,
		Name:      "theowner",
	}, owner)
}

func TestTopOwnerLabel(t *testing.T) {
	type testCase struct {
		expectedLabel OwnerLabel
		expectedName  string
		expectedKind  string
		owner         *Owner
	}
	for _, tc := range []testCase{
		{expectedLabel: OwnerDaemonSet, expectedName: "ds", expectedKind: "DaemonSet",
			owner: &Owner{LabelName: OwnerDaemonSet, Name: "ds", Kind: "DaemonSet"}},
		{expectedLabel: OwnerDeployment, expectedName: "rs-without-dep-meta", expectedKind: "Deployment",
			owner: &Owner{LabelName: OwnerReplicaSet, Name: "rs-without-dep-meta-34fb1fa3a", Kind: "ReplicaSet"}},
		{expectedLabel: OwnerDeployment, expectedName: "dep", expectedKind: "Deployment",
			owner: &Owner{LabelName: OwnerReplicaSet, Name: "dep-34fb1fa3a", Kind: "ReplicaSet",
				Owner: &Owner{LabelName: OwnerDeployment, Name: "dep", Kind: "Deployment"}}},
	} {
		t.Run(tc.expectedName, func(t *testing.T) {
			topOwner := tc.owner.TopOwner()
			assert.Equal(t, tc.expectedName, topOwner.Name)
			assert.Equal(t, tc.expectedLabel, topOwner.LabelName)
			assert.Equal(t, tc.expectedKind, topOwner.Kind)

			// check that the output is consistent (e.g. after ReplicaSet owner data is cached)
			topOwner = tc.owner.TopOwner()
			assert.Equal(t, tc.expectedName, topOwner.Name)
			assert.Equal(t, tc.expectedLabel, topOwner.LabelName)
			assert.Equal(t, tc.expectedKind, topOwner.Kind)
		})
	}
}

func TestTopOwner_Nil(t *testing.T) {
	assert.Nil(t, (*Owner)(nil).TopOwner())
}
