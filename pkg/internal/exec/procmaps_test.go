package exec

import (
	"testing"

	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
)

func TestModulePathMatching(t *testing.T) {

	maps := makeProcFSMaps([]string{"/something/something/libssl.so.3", "anon_inode:[io_uring]"})

	assert.Nil(t, LibPath("node", maps))
	assert.Equal(t, procPSFromPath("/something/something/libssl.so.3"), LibPath("libssl.so", maps))

	maps = makeProcFSMaps([]string{"libssl.so", "/node"})

	assert.Equal(t, procPSFromPath("/node"), LibPath("node", maps))
	assert.Nil(t, LibPath("libssl.so", maps))
}

func makeProcFSMaps(paths []string) []*procfs.ProcMap {
	res := []*procfs.ProcMap{}

	for _, path := range paths {
		p := procfs.ProcMap{Pathname: path, Perms: &procfs.ProcMapPermissions{Execute: true}}
		res = append(res, &p)
	}

	return res
}

func procPSFromPath(path string) *procfs.ProcMap {
	return &procfs.ProcMap{Pathname: path, Perms: &procfs.ProcMapPermissions{Execute: true}}
}
