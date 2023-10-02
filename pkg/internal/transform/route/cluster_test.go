package route

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestURLClustering(t *testing.T) {
	err := InitAutoClassifier()
	assert.NoError(t, err)
	assert.Equal(t, "", ClusterPath(""))
	assert.Equal(t, "/users/*/*/*/job/*", ClusterPath("/users/fdklsd/j4elk/23993/job/2"))
	assert.Equal(t, "*", ClusterPath("123"))
	assert.Equal(t, "/*", ClusterPath("/123"))
	assert.Equal(t, "*/", ClusterPath("123/"))
	assert.Equal(t, "*/*", ClusterPath("123/ljgdflgjf"))
	assert.Equal(t, "/*", ClusterPath("/**"))
	assert.Equal(t, "/u/*", ClusterPath("/u/2"))
	assert.Equal(t, "/products/*/org/*", ClusterPath("/products/1/org/3"))
	assert.Equal(t, "/products//org/*", ClusterPath("/products//org/3"))
	assert.Equal(t, "/attach", ClusterPath("/attach"))
	assert.Equal(t, "/usuarios/*/*/*/trabajo/*", ClusterPath("/usuarios/fdklsd/j4elk/23993/trabajo/2"))
	assert.Equal(t, "/Benutzer/*/*/*/Arbeit/*", ClusterPath("/Benutzer/fdklsd/j4elk/23993/Arbeit/2"))
	assert.Equal(t, "/utilisateurs/*/*/*/tache/*", ClusterPath("/utilisateurs/fdklsd/j4elk/23993/tache/2"))
	assert.Equal(t, "/products/", ClusterPath("/products/"))
	assert.Equal(t, "/user-space/", ClusterPath("/user-space/"))
	assert.Equal(t, "/user_space/", ClusterPath("/user_space/"))
}
