package route

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURLClustering(t *testing.T) {
	err := InitAutoClassifier()

	wildCard := "*"

	assert.NoError(t, err)
	assert.Equal(t, "", ClusterPath("", wildCard))
	assert.Equal(t, "/", ClusterPath("/", wildCard))
	assert.Equal(t, "/users/*/j4elk/*/job/*", ClusterPath("/users/fdklsd/j4elk/23993/job/2", wildCard))
	assert.Equal(t, "*", ClusterPath("123", wildCard))
	assert.Equal(t, "/*", ClusterPath("/123", wildCard))
	assert.Equal(t, "*/", ClusterPath("123/", wildCard))
	assert.Equal(t, "*/*", ClusterPath("123/ljgdflgjf", wildCard))
	assert.Equal(t, "/*", ClusterPath("/**", wildCard))
	assert.Equal(t, "/u/*", ClusterPath("/u/2", wildCard))
	assert.Equal(t, "/v1/products/*", ClusterPath("/v1/products/2", wildCard))
	assert.Equal(t, "/v1/products/*", ClusterPath("/v1/products/22", wildCard))
	assert.Equal(t, "/v1/products/*", ClusterPath("/v1/products/22j", wildCard))
	assert.Equal(t, "/products/*/org/*", ClusterPath("/products/1/org/3", wildCard))
	assert.Equal(t, "/products//org/*", ClusterPath("/products//org/3", wildCard))
	assert.Equal(t, "/v1/k6-test-runs/*", ClusterPath("/v1/k6-test-runs/1", wildCard))
	assert.Equal(t, "/attach", ClusterPath("/attach", wildCard))
	assert.Equal(t, "/usuarios/*/j4elk/*/trabajo/*", ClusterPath("/usuarios/fdklsd/j4elk/23993/trabajo/2", wildCard))
	assert.Equal(t, "/Benutzer/*/j4elk/*/Arbeit/*", ClusterPath("/Benutzer/fdklsd/j4elk/23993/Arbeit/2", wildCard))
	assert.Equal(t, "/utilisateurs/*/j4elk/*/tache/*", ClusterPath("/utilisateurs/fdklsd/j4elk/23993/tache/2", wildCard))
	assert.Equal(t, "/products/", ClusterPath("/products/", wildCard))
	assert.Equal(t, "/user-space/", ClusterPath("/user-space/", wildCard))
	assert.Equal(t, "/user_space/", ClusterPath("/user_space/", wildCard))
}
