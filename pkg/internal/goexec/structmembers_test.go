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

	"github.com/grafana/beyla/v2/test/tools"
)

var debugData *dwarf.Data
var grpcElf *dwarf.Data
var smallELF *elf.File
var smallGRPCElf *elf.File

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
	smallELF = compileELF(baseDir+"/test/cmd/pingserver/server.go", "-ldflags", "-s -w")
	grpcElf, err = compileELF(baseDir + "/test/cmd/grpc/server/server.go").DWARF()
	if err != nil {
		panic(err)
	}
	smallGRPCElf = compileELF(baseDir+"/test/cmd/grpc/server/server.go", "-ldflags", "-s -w")
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
		URLPtrPos:         uint64(16),
		PathPtrPos:        uint64(56),
		ConnFdPos:         uint64(0),
		FdLaddrPos:        uint64(96),
		MethodPtrPos:      uint64(0),
		TCPAddrIPPtrPos:   uint64(0),
		TCPAddrPortPtrPos: uint64(24),
	}, offsets)
}

func TestGrpcOffsetsFromDwarf(t *testing.T) {
	offsets, _ := structMemberOffsetsFromDwarf(grpcElf)
	// this test might fail if a future Go gRPC version updates the internal structure of the used structs.
	mustMatch(t, FieldOffsets{
		GrpcStreamStPtrPos:     uint64(8),
		GrpcStreamMethodPtrPos: uint64(88),
		GrpcStatusSPos:         uint64(0),
		ConnFdPos:              uint64(0),
		FdLaddrPos:             uint64(96),
		GrpcStatusCodePtrPos:   uint64(40),
	}, offsets)
}

func TestGoOffsetsWithoutDwarf(t *testing.T) {
	offsets, err := structMemberOffsets(smallELF)
	require.NoError(t, err)
	// this test might fail if a future Go version updates the internal structure of the used structs.
	mustMatch(t, FieldOffsets{
		URLPtrPos:    uint64(16),
		PathPtrPos:   uint64(56),
		ConnFdPos:    uint64(0),
		FdLaddrPos:   uint64(96),
		MethodPtrPos: uint64(0),
	}, offsets)
}

func TestGrpcOffsetsWithoutDwarf(t *testing.T) {
	offsets, _ := structMemberOffsets(smallGRPCElf)
	// this test might fail if a future Go gRPC version updates the internal structure of the used structs.
	mustMatch(t, FieldOffsets{
		GrpcStreamStPtrPos:     uint64(8),
		GrpcStreamMethodPtrPos: uint64(88),
		GrpcStatusSPos:         uint64(0),
		GrpcStatusCodePtrPos:   uint64(40),
		ConnFdPos:              uint64(0),
		FdLaddrPos:             uint64(96),
	}, offsets)
}

func TestGoOffsetsFromDwarf_ErrorIfConstantNotFound(t *testing.T) {
	structMembers["net/http.response"] = structInfo{
		lib: "go",
		fields: map[string]GoOffset{
			"tralara": 123456,
		},
	}
	_, missing := structMemberOffsetsFromDwarf(debugData)
	assert.Contains(t, missing, GoOffset(123456))
}

func TestReadMembers_UnsupportedLocationType(t *testing.T) {
	fdr := &fakeDwarfReader{
		entries: []*dwarf.Entry{{
			Tag: dwarf.TagStructType,
			Field: []dwarf.Field{
				{Attr: dwarf.AttrName, Val: "supported_loc"},
				{Attr: dwarf.AttrDataMemberLoc, Val: int64(33)},
			},
		}, {
			Tag: dwarf.TagStructType,
			Field: []dwarf.Field{
				{Attr: dwarf.AttrName, Val: "unsupported_loc"},
				{Attr: dwarf.AttrDataMemberLoc, Val: []byte("#\x00")},
			}},
		},
	}
	notFoundFields := map[GoOffset]struct{}{
		123456: {},
		234567: {},
	}
	// Must return an error if there is a field with unsupported location type
	require.Error(t, readMembers(fdr, map[string]GoOffset{
		"supported_loc":   123456,
		"unsupported_loc": 234567,
	}, notFoundFields, FieldOffsets{}))
	// And this field will be kept in the "expectedFields" map, so Beyla will
	// later know that it didn't manage to get that information from dwarf
	// and will try to look for it in the precompiled offsets DB
	assert.Equal(t, map[GoOffset]struct{}{
		234567: {},
	}, notFoundFields)
}

type fakeDwarfReader struct {
	entries []*dwarf.Entry
}

func (f *fakeDwarfReader) Next() (*dwarf.Entry, error) {
	if len(f.entries) == 0 {
		return nil, nil
	}
	entry := f.entries[0]
	f.entries = f.entries[1:]
	return entry, nil
}
