package kube

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestServiceName(t *testing.T) {
	pod := PodInfo{
		Owner: &Owner{
			Name: "nested_one",
		},
	}

	pod2 := PodInfo{
		Owner: &Owner{
			Owner: &Owner{
				Name: "nested_two",
			},
		},
	}

	pod3 := PodInfo{
		Owner: &Owner{
			Owner: &Owner{
				Owner: &Owner{
					Name: "nested_three",
				},
			},
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "too_nested",
		},
	}

	pod4 := PodInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name: "not_nested",
		},
	}

	pod5 := PodInfo{}

	assert.Equal(t, "nested_one", pod.ServiceName())
	assert.Equal(t, "nested_two", pod2.ServiceName())
	assert.Equal(t, "", pod3.ServiceName())
	assert.Equal(t, "not_nested", pod4.ServiceName())
	assert.Equal(t, "", pod5.ServiceName())
}
