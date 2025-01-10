package route

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURLClustering(t *testing.T) {
	err := InitAutoClassifier()
	assert.NoError(t, err)

	for _, tc := range []byte{'*', '#', '_', '-'} {
		tcString := string(tc)

		t.Run(tcString, func(t *testing.T) {
			assert.Equal(t, "", ClusterPath("", tc))
			assert.Equal(t, "/", ClusterPath("/", tc))
			assert.Equal(t, fmt.Sprintf("/users/%[1]s/j4elk/%[1]s/job/%[1]s", tcString), ClusterPath("/users/fdklsd/j4elk/23993/job/2", tc))
			assert.Equal(t, tcString, ClusterPath("123", tc))
			assert.Equal(t, fmt.Sprintf("/%s", tcString), ClusterPath("/123", tc))
			assert.Equal(t, fmt.Sprintf("%s/", tcString), ClusterPath("123/", tc))
			assert.Equal(t, fmt.Sprintf("%[1]s/%[1]s", tcString), ClusterPath("123/ljgdflgjf", tc))
			assert.Equal(t, fmt.Sprintf("/%s", tcString), ClusterPath("/**", tc))
			assert.Equal(t, fmt.Sprintf("/u/%s", tcString), ClusterPath("/u/2", tc))
			assert.Equal(t, fmt.Sprintf("/v1/products/%s", tcString), ClusterPath("/v1/products/2", tc))
			assert.Equal(t, fmt.Sprintf("/v1/products/%s", tcString), ClusterPath("/v1/products/22", tc))
			assert.Equal(t, fmt.Sprintf("/v1/products/%s", tcString), ClusterPath("/v1/products/22j", tc))
			assert.Equal(t, fmt.Sprintf("/products/%[1]s/org/%[1]s", tcString), ClusterPath("/products/1/org/3", tc))
			assert.Equal(t, fmt.Sprintf("/products//org/%s", tcString), ClusterPath("/products//org/3", tc))
			assert.Equal(t, fmt.Sprintf("/v1/k6-test-runs/%s", tcString), ClusterPath("/v1/k6-test-runs/1", tc))
			assert.Equal(t, "/attach", ClusterPath("/attach", tc))
			assert.Equal(t, fmt.Sprintf("/usuarios/%[1]s/j4elk/%[1]s/trabajo/%[1]s", tcString), ClusterPath("/usuarios/fdklsd/j4elk/23993/trabajo/2", tc))
			assert.Equal(t, fmt.Sprintf("/Benutzer/%[1]s/j4elk/%[1]s/Arbeit/%[1]s", tcString), ClusterPath("/Benutzer/fdklsd/j4elk/23993/Arbeit/2", tc))
			assert.Equal(t, fmt.Sprintf("/utilisateurs/%[1]s/j4elk/%[1]s/tache/%[1]s", tcString), ClusterPath("/utilisateurs/fdklsd/j4elk/23993/tache/2", tc))
			assert.Equal(t, "/products/", ClusterPath("/products/", tc))
			assert.Equal(t, "/user-space/", ClusterPath("/user-space/", tc))
			assert.Equal(t, "/user_space/", ClusterPath("/user_space/", tc))
		})
	}
}
