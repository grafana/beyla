package kube

import (
	"testing"

	"github.com/grafana/beyla/pkg/internal/helpers/container"
	"github.com/grafana/beyla/pkg/internal/kube"
	"github.com/stretchr/testify/assert"
)

func Test_NamespaceReuse(t *testing.T) {
	db := CreateDatabase(&kube.Metadata{})
	ifp := container.Info{
		ContainerID:  "a",
		PIDNamespace: 111,
	}
	db.addProcess(&ifp)
	// pretend we resolved some pod info earlier
	db.fetchedPodsCache[ifp.PIDNamespace] = &kube.PodInfo{NodeName: "a"}
	info, err := db.OwnerPodInfo(111)
	assert.True(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "a", info.NodeName)

	_, ok := db.fetchedPodsCache[ifp.PIDNamespace]
	assert.True(t, ok)

	ifp1 := container.Info{
		ContainerID:  "b",
		PIDNamespace: ifp.PIDNamespace,
	}

	// We overwrite the container info with new namespace
	db.addProcess(&ifp1)
	_, ok = db.fetchedPodsCache[ifp.PIDNamespace]
	assert.False(t, ok)
}

func Test_NamespaceCacheCleanup(t *testing.T) {
	db := CreateDatabase(&kube.Metadata{})
	ifp := container.Info{
		ContainerID:  "a",
		PIDNamespace: 111,
	}
	db.addProcess(&ifp)
	// pretend we resolved some pod info earlier
	db.fetchedPodsCache[ifp.PIDNamespace] = &kube.PodInfo{NodeName: "a"}
	info, err := db.OwnerPodInfo(111)
	assert.True(t, err)
	assert.NotNil(t, info)
	assert.Equal(t, "a", info.NodeName)

	_, ok := db.fetchedPodsCache[ifp.PIDNamespace]
	assert.True(t, ok)

	// We overwrite the container info with new namespace
	db.CleanProcessCaches(ifp.PIDNamespace)
	_, ok = db.fetchedPodsCache[ifp.PIDNamespace]
	assert.False(t, ok)
}
