package kube

import (
	"os"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

type IndexerMock struct {
	mock.Mock
	cache.Indexer
}

type InformerMock struct {
	mock.Mock
	InformerInterface
}

type InformerInterface interface {
	cache.SharedInformer
	AddIndexers(indexers cache.Indexers) error
	GetIndexer() cache.Indexer
}

func (indexMock *IndexerMock) ByIndex(indexName, indexedValue string) ([]interface{}, error) {
	args := indexMock.Called(indexName, indexedValue)
	return args.Get(0).([]interface{}), args.Error(1)
}

func (informerMock *InformerMock) GetIndexer() cache.Indexer {
	args := informerMock.Called()
	return args.Get(0).(cache.Indexer)
}

func TestGetPodInfoByIP(t *testing.T) {
	kubeData := Metadata{}
	// pods informer
	pidx := IndexerMock{}
	pidx.On("ByIndex", IndexPodIPs, "10.0.0.1").Return([]interface{}{}, os.ErrNotExist)
	pidx.On("ByIndex", IndexPodIPs, "1.2.3.4").Return([]interface{}{&PodInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podName",
			Namespace: "podNamespace",
			OwnerReferences: []metav1.OwnerReference{{
				Kind:       "ReplicaSet",
				APIVersion: "apps/v1",
				Name:       "bar-456",
			}},
		},
	}}, nil)
	pim := InformerMock{}
	pim.On("GetIndexer").Return(&pidx)

	kubeData.pods = &pim

	info, ok := kubeData.GetPodInfo("1.2.3.4")
	require.True(t, ok)

	require.Equal(t, PodInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podName",
			Namespace: "podNamespace",
		},
		ReplicaSetName: "bar-456",
	}, *info)
}

func TestGetReplicaSetInfoByName(t *testing.T) {
	kubeData := Metadata{}
	// rs informer
	pidx := IndexerMock{}
	pidx.On("ByIndex", IndexReplicaSetNames, "bar-456").Return([]interface{}{&ReplicaSetInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rs",
			Namespace: "rsNs",
			OwnerReferences: []metav1.OwnerReference{{
				Kind:       "Deployment",
				APIVersion: "apps/v1",
				Name:       "foo-333",
			}},
		},
	}}, nil)
	pim := InformerMock{}
	pim.On("GetIndexer").Return(&pidx)

	kubeData.replicaSets = &pim

	info, ok := kubeData.GetPodInfo("bar-456")
	require.True(t, ok)

	require.Equal(t, *info, ReplicaSetInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rs",
			Namespace: "rsns",
		},
		DeploymentName: "foo-333",
	})
}
