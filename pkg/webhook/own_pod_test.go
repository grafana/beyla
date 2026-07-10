package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func TestOwnNodePod(t *testing.T) {
	const (
		ns          = "beyla-system"
		node        = "node-1"
		containerID = "abc123def456"
	)

	t.Run("returns the pod whose container id matches", func(t *testing.T) {
		ourPod := makePod("beyla-xyz", ns, node, containerID, nil)
		other := makePod("other", ns, node, "ffffeeeeddddcccc", nil)
		client := fake.NewSimpleClientset(ourPod, other)

		got, err := ownNodePod(t.Context(), client, ns, containerID)
		require.NoError(t, err)
		assert.Equal(t, "beyla-xyz", got.Name)
	})

	t.Run("errors when no pod matches the container id", func(t *testing.T) {
		other := makePod("not-us", ns, node, "ffffeeeeddddcccc", nil)
		client := fake.NewSimpleClientset(other)

		_, err := ownNodePod(t.Context(), client, ns, containerID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not find own pod")
	})

	t.Run("errors when no pods exist in the namespace", func(t *testing.T) {
		client := fake.NewSimpleClientset()

		_, err := ownNodePod(t.Context(), client, ns, containerID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not find own pod")
	})

	t.Run("propagates list errors", func(t *testing.T) {
		client := fake.NewSimpleClientset()
		client.PrependReactor("list", "pods", func(_ clienttesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewServiceUnavailable("apiserver down")
		})

		_, err := ownNodePod(t.Context(), client, ns, containerID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "list pods")
		assert.Contains(t, err.Error(), "apiserver down")
	})

	t.Run("matches when status container id has a runtime scheme prefix", func(t *testing.T) {
		ourPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "beyla", Namespace: ns},
			Spec:       corev1.PodSpec{NodeName: node},
			Status: corev1.PodStatus{
				ContainerStatuses: []corev1.ContainerStatus{
					{Name: "main", ContainerID: "cri-o://" + containerID},
				},
			},
		}
		client := fake.NewSimpleClientset(ourPod)

		got, err := ownNodePod(t.Context(), client, ns, containerID)
		require.NoError(t, err)
		assert.Equal(t, "beyla", got.Name)
	})
}
