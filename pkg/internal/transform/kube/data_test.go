/*
 * Copyright (C) 2023 Grafana Labs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Part of this his code is a revision of the code found in:
 * https://github.com/netobserv/flowlogs-pipeline/ (Apache 2.0 license)
 */

package kube



import (
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

type KubeDataMock struct {
	mock.Mock
	kubeDataInterface
}

func (o *KubeDataMock) InitFromConfig(kubeConfigPath string) error {
	args := o.Called(kubeConfigPath)
	return args.Error(0)
}

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

func TestGetInfoPods(t *testing.T) {
	kubeData := Metadata{}
	// pods informer
	pidx := IndexerMock{}
	pidx.On("ByIndex", IndexIP, "1.2.3.4").Return([]interface{}{&Info{
		Type: "Pod",
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podName",
			Namespace: "podNamespace",
		},
		HostIP: "10.0.0.1",
		Owner:  Owner{Name: "podName", Type: "Pod"},
	}}, nil)
	pim := InformerMock{}
	pim.On("GetIndexer").Return(&pidx)
	// nodes informer
	hidx := IndexerMock{}
	hidx.On("ByIndex", IndexIP, "10.0.0.1").Return([]interface{}{&Info{
		Type: "Node",
		ObjectMeta: metav1.ObjectMeta{
			Name: "nodeName",
		},
	}}, nil)
	him := InformerMock{}
	him.On("GetIndexer").Return(&hidx)

	kubeData.pods = &pim
	kubeData.nodes = &him
	info, err := kubeData.GetInfo("1.2.3.4")
	require.NoError(t, err)

	require.Equal(t, *info, Info{
		Type: "Pod",
		ObjectMeta: metav1.ObjectMeta{
			Name:      "podName",
			Namespace: "podNamespace",
		},
		HostName: "nodeName",
		HostIP:   "10.0.0.1",
		Owner:    Owner{Name: "podName", Type: "Pod"},
	})
}
