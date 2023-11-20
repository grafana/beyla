package container

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fixtureContainerID = "40c03570b6f4c30bc8d69923d37ee698f5cfcced92c7b7df1c47f6f7887378a9"

func TestContainerID(t *testing.T) {
	procRoot = "./fixtures/"
	info, err := InfoForPID(123)
	require.NoError(t, err)
	assert.Equal(t, fixtureContainerID, info.ContainerID)
	info, err = InfoForPID(456)
	require.NoError(t, err)
	assert.Equal(t, fixtureContainerID, info.ContainerID)

	_, err = InfoForPID(789)
	require.Error(t, err)
	_, err = InfoForPID(1011)
	require.Error(t, err)

}
