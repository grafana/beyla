package webhook

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindCgroup(t *testing.T) {
	tests := []struct {
		name          string
		cgroupEntry   string
		expectedID    string
		expectedFound bool
	}{
		{
			name:          "docker format with scope",
			cgroupEntry:   "0::/docker/abc123def456/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod123.slice/cri-containerd-1234567890abcdef.scope",
			expectedID:    "1234567890abcdef",
			expectedFound: true,
		},
		{
			name:          "GKE format",
			cgroupEntry:   "0::/kubepods/burstable/pod4a163a05-439d-484b-8e53-2968bc15824f/cde6dfaf5007ed65aad2d6aed72af91b0f3d95813492f773286e29ae145d20f4",
			expectedID:    "cde6dfaf5007ed65aad2d6aed72af91b0f3d95813492f773286e29ae145d20f4",
			expectedFound: true,
		},
		{
			name:          "EKS format",
			cgroupEntry:   "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-poddde1244b_5bb5_4297_b544_85f3bc0d80bf.slice/cri-containerd-acb62391578595ec849d87d8556369cee7f935f0425097fd5f870df0e8aabd3c.scope",
			expectedID:    "acb62391578595ec849d87d8556369cee7f935f0425097fd5f870df0e8aabd3c",
			expectedFound: true,
		},
		{
			name:          "containerd format",
			cgroupEntry:   "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod7260904bbd08e72e4dff95d9fccd2ee8.slice/cri-containerd-d36686f9785534531160dc936aec9d711a26eb37f4fc7752a2ae27d0a24345c1.scope",
			expectedID:    "d36686f9785534531160dc936aec9d711a26eb37f4fc7752a2ae27d0a24345c1",
			expectedFound: true,
		},
		{
			name:          "k8s.io format",
			cgroupEntry:   "0::/k8s.io/1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectedID:    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expectedFound: true,
		},
		{
			name:          "fallback docker format",
			cgroupEntry:   "0::/../../pode039200acb850c82bb901653cc38ff6e/58452031ab6dcaa4fe3ff91f8a46fd41a4a2405586f3cf3d5cb9c93b5bcf62cc",
			expectedID:    "58452031ab6dcaa4fe3ff91f8a46fd41a4a2405586f3cf3d5cb9c93b5bcf62cc",
			expectedFound: true,
		},
		{
			name:          "no match - invalid format",
			cgroupEntry:   "0::/system.slice/docker.service",
			expectedID:    "",
			expectedFound: false,
		},
		{
			name:          "empty string",
			cgroupEntry:   "",
			expectedID:    "",
			expectedFound: false,
		},
		{
			name:          "short container ID",
			cgroupEntry:   "0::/docker/shortid",
			expectedID:    "",
			expectedFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, found := findCgroup(tt.cgroupEntry)
			assert.Equal(t, tt.expectedFound, found)
			assert.Equal(t, tt.expectedID, id)
		})
	}
}

func TestContainerInfoForPID(t *testing.T) {
	// Create temporary directory structure for testing
	tempDir := t.TempDir()

	// Save and restore original values
	origProcRoot := procRoot
	origNamespaceFinder := namespaceFinder
	defer func() {
		procRoot = origProcRoot
		namespaceFinder = origNamespaceFinder
	}()

	procRoot = tempDir + "/"

	t.Run("successful container info extraction", func(t *testing.T) {
		// Setup mock namespace finder
		namespaceFinder = func(pid int32) (uint32, error) {
			return 12345, nil
		}

		// Create mock cgroup file
		pid := uint32(9999)
		pidDir := filepath.Join(tempDir, "9999")
		err := os.MkdirAll(pidDir, 0755)
		require.NoError(t, err)

		cgroupContent := `12:pids:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123.slice/cri-containerd-abc123def456abc123def456abc123def456abc123def456abc123def456abc1.scope
11:cpuset:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123.slice/cri-containerd-abc123def456abc123def456abc123def456abc123def456abc123def456abc1.scope
0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123.slice/cri-containerd-abc123def456abc123def456abc123def456abc123def456abc123def456abc1.scope`

		err = os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(cgroupContent), 0644)
		require.NoError(t, err)

		// Test
		info, err := containerInfoForPID(pid)
		require.NoError(t, err)
		assert.Equal(t, uint32(12345), info.PIDNamespace)
		assert.Equal(t, "abc123def456abc123def456abc123def456abc123def456abc123def456abc1", info.ContainerID)
	})

	t.Run("cgroup file not found", func(t *testing.T) {
		namespaceFinder = func(pid int32) (uint32, error) {
			return 12345, nil
		}

		pid := uint32(8888)

		_, err := containerInfoForPID(pid)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reading")
	})

	t.Run("no valid cgroup entry", func(t *testing.T) {
		namespaceFinder = func(pid int32) (uint32, error) {
			return 12345, nil
		}

		pid := uint32(7777)
		pidDir := filepath.Join(tempDir, "7777")
		err := os.MkdirAll(pidDir, 0755)
		require.NoError(t, err)

		cgroupContent := `12:pids:/system.slice/docker.service
11:cpuset:/system.slice
0::/system.slice`

		err = os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(cgroupContent), 0644)
		require.NoError(t, err)

		_, err = containerInfoForPID(pid)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "couldn't find any docker entry")
	})

	t.Run("namespace finder fails", func(t *testing.T) {
		namespaceFinder = func(pid int32) (uint32, error) {
			return 0, assert.AnError
		}

		pid := uint32(6666)
		pidDir := filepath.Join(tempDir, "6666")
		err := os.MkdirAll(pidDir, 0755)
		require.NoError(t, err)

		err = os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte("0::/test"), 0644)
		require.NoError(t, err)

		_, err = containerInfoForPID(pid)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "finding PID")
	})
}
