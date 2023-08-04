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

func TestGetInfoByIP(t *testing.T) {
	kubeData := Metadata{}
	// pods informer
	pidx := IndexerMock{}
	pidx.On("ByIndex", IndexIPOrName, "10.0.0.1").Return([]interface{}{}, os.ErrNotExist)
	pidx.On("ByIndex", IndexIPOrName, "1.2.3.4").Return([]interface{}{&Info{
		Type: "Pod",
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podName",
			Namespace: "podNamespace",
		},
	}}, nil)
	pim := InformerMock{}
	pim.On("GetIndexer").Return(&pidx)
	// Services informer
	hidx := IndexerMock{}
	hidx.On("ByIndex", IndexIPOrName, "10.0.0.1").Return([]interface{}{&Info{
		Type: "Service",
		ObjectMeta: metav1.ObjectMeta{
			Name: "serviceName",
		},
	}}, nil)
	sim := InformerMock{}
	sim.On("GetIndexer").Return(&hidx)

	kubeData.pods = &pim
	kubeData.services = &sim

	info, ok := kubeData.GetInfo("1.2.3.4")
	require.True(t, ok)

	require.Equal(t, *info, Info{
		Type: "Pod",
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podName",
			Namespace: "podNamespace",
		},
	})

	info, ok = kubeData.GetInfo("10.0.0.1")
	require.True(t, ok)

	require.Equal(t, *info, Info{
		Type: "Service",
		ObjectMeta: metav1.ObjectMeta{
			Name: "serviceName",
		},
	})
}
