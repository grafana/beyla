package integration

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func PrintFreeStorage(t *testing.T) {
	var stat unix.Statfs_t
	wd, err := os.Getwd()
	if err == nil && unix.Statfs(wd, &stat) == nil {
		t.Logf("Free storage space (in %s) is: %dMB\n", wd, stat.Bavail*uint64(stat.Bsize)/(1024*1024))
	}
}

func PrintDockerStorage(t *testing.T) {
	PrintFreeStorage(t)
	out, err := exec.Command("docker", "system", "df").CombinedOutput()
	require.NoError(t, err)
	if err == nil {
		t.Logf("Docker system df output:\n%s", string(out))
	}
	out, err = exec.Command("docker", "images").CombinedOutput()
	require.NoError(t, err)
	if err == nil {
		t.Logf("Docker images:\n%s", string(out))
	}
}

func DockerPrune(t *testing.T) {
	out, err := exec.Command("docker", "system", "prune", "-f").CombinedOutput()
	require.NoError(t, err)
	if err == nil {
		t.Logf("Docker system prune -f:\n %s", string(out))
	}
	out, err = exec.Command("docker", "volume", "prune", "-f").CombinedOutput()
	require.NoError(t, err)
	if err == nil {
		t.Logf("Docker volume prune -f:\n %s", string(out))
	}
}
