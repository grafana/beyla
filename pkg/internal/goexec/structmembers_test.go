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

	"github.com/grafana/beyla/test/tools"
)

var debugData *dwarf.Data
var grpcElf *dwarf.Data
var smallELF *elf.File

func compileELF(source string, extraArgs ...string) *elf.File {
	tempDir := os.TempDir()
	tmpFilePath := path.Join(tempDir, "server.testexec")
	cmdParts := []string{"build"}
	cmdParts = append(cmdParts, extraArgs...)
	cmdParts = append(cmdParts, "-o", tmpFilePath, source)
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
	baseDir := tools.ProjectDir()
	// Compiling the same executable twice, with and without debug data so we can inspect it later in the tests
	debugData, err = compileELF(baseDir + "/test/cmd/pingserver/server.go").DWARF()
	if err != nil {
		panic(err)
	}
	grpcElf, _ = compileELF(baseDir + "/test/cmd/grpc/server/server.go").DWARF()
	smallELF = compileELF(baseDir+"/test/cmd/pingserver/server.go", "-ldflags", "-s -w")
	m.Run()
}

func mustMatch(t *testing.T, expected, actual FieldOffsets) {
	for key, value := range expected {
		assert.Equal(t, value, actual[key], "key: %s", key)
	}
}

func TestGoOffsetsFromDwarf(t *testing.T) {
	offsets, _ := structMemberOffsetsFromDwarf(debugData)
	// this test might fail if a future Go version updates the internal structure of the used structs.
	mustMatch(t, FieldOffsets{
		"url_ptr_pos":           uint64(16),
		"path_ptr_pos":          uint64(56),
		"remoteaddr_ptr_pos":    uint64(176),
		"host_ptr_pos":          uint64(128),
		"method_ptr_pos":        uint64(0),
		"status_ptr_pos":        uint64(120),
		"tcp_addr_ip_ptr_pos":   uint64(0),
		"tcp_addr_port_ptr_pos": uint64(24),
		"resp_req_pos":          uint64(8),
	}, offsets)
}

func TestGrpcOffsetsFromDwarf(t *testing.T) {
	offsets, _ := structMemberOffsetsFromDwarf(grpcElf)
	// this test might fail if a future Go gRPC version updates the internal structure of the used structs.
	mustMatch(t, FieldOffsets{
		"grpc_stream_st_ptr_pos":     uint64(8),
		"grpc_stream_method_ptr_pos": uint64(80),
		"grpc_status_s_pos":          uint64(0),
		"grpc_status_code_ptr_pos":   uint64(40),
		"grpc_st_remoteaddr_ptr_pos": uint64(72),
		"grpc_st_localaddr_ptr_pos":  uint64(88),
		"grpc_client_target_ptr_pos": uint64(24),
	}, offsets)
}

func TestGoOffsetsWithoutDwarf(t *testing.T) {
	offsets, err := structMemberOffsets(smallELF)
	require.NoError(t, err)
	// this test might fail if a future Go version updates the internal structure of the used structs.
	mustMatch(t, FieldOffsets{
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
	_, missing := structMemberOffsetsFromDwarf(debugData)
	assert.Contains(t, missing, "tralara")
}
