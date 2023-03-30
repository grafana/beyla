package goexec

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var debugData *dwarf.Data
var smallELF *elf.File

func compileELF(extraArgs ...string) *elf.File {
	tempDir := os.TempDir()
	tmpFilePath := path.Join(tempDir, "server.testexec")
	cmdParts := []string{"build"}
	cmdParts = append(cmdParts, extraArgs...)
	cmdParts = append(cmdParts, "-o", tmpFilePath, "../../test/cmd/pingserver/server.go")
	cmd := exec.Command("go", cmdParts...)
	cmd.Env = []string{"GOOS=linux", "HOME=" + tempDir}
	out := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Run(); err != nil {
		fmt.Println("command output:\n" + out.String())
		panic(err)
	}
	execELF, err := elf.Open(tmpFilePath)
	if err != nil {
		panic(err)
	}
	return execELF
}

func TestMain(m *testing.M) {
	var err error
	// Compiling the same executable twice, with and without debug data so we can inspect it later in the tests
	debugData, err = compileELF().DWARF()
	if err != nil {
		panic(err)
	}
	smallELF = compileELF("-ldflags", "-s -w")
	m.Run()
}

func TestGoOffsetsFromDwarf(t *testing.T) {
	offsets, err := structMemberOffsetsFromDwarf(debugData)
	require.NoError(t, err)
	// this test might fail if a future Go version updates the internal structure of the used structs.
	assert.Equal(t, FieldOffsets{
		"url_ptr_pos":        uint64(16),
		"path_ptr_pos":       uint64(56),
		"remoteaddr_ptr_pos": uint64(176),
		"host_ptr_pos":       uint64(128),
		"method_ptr_pos":     uint64(0),
		"status_ptr_pos":     uint64(120),
	}, offsets)
}

func TestGoOffsetsWithoutDwarf(t *testing.T) {
	offsets, err := structMemberOffsets(smallELF)
	require.NoError(t, err)
	// this test might fail if a future Go version updates the internal structure of the used structs.
	assert.Equal(t, FieldOffsets{
		"url_ptr_pos":        uint64(16),
		"path_ptr_pos":       uint64(56),
		"remoteaddr_ptr_pos": uint64(176),
		"host_ptr_pos":       uint64(128),
		"method_ptr_pos":     uint64(0),
		"status_ptr_pos":     uint64(120),
	}, offsets)
}

func TestGoOffsetsFromDwarf_ErrorIfConstantNotFound(t *testing.T) {
	structMembers["net/http.response"] = structInfo{
		lib: "go",
		fields: map[string]string{
			"tralara": "tralara",
		},
	}
	_, err := structMemberOffsetsFromDwarf(debugData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tralara")
}
