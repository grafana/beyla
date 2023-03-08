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

func TestMain(m *testing.M) {
	// Compiling a go executable with debug data so we can inspect it later in the tests
	tempDir := os.TempDir()
	tmpFilePath := path.Join(tempDir, "server.testexec")
	cmd := exec.Command("go", "build", "-o", tmpFilePath, "../../test/cmd/pingserver/server.go")
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
	debugData, err = execELF.DWARF()
	if err != nil {
		panic(err)
	}
	m.Run()
}

func TestGoOffsetsFromDwarf(t *testing.T) {
	offsets, err := structMemberOffsetsFromDwarf(debugData)
	require.NoError(t, err)
	// this test might fail if a future Go version updates the internal structure of the used structs.
	assert.Equal(t, FieldOffsets{
		"url_ptr_pos":    uint64(16),
		"path_ptr_pos":   uint64(56),
		"method_ptr_pos": uint64(0),
		"status_ptr_pos": uint64(120),
	}, offsets)
}

func TestGoOffsetsFromDwarf_ErrorIfConstantNotFound(t *testing.T) {
	structMembers["net/http.response"] = map[string]string{
		"tralara": "tralara",
	}
	_, err := structMemberOffsetsFromDwarf(debugData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tralara")
}
