package fs

import (
	"os"
	"path/filepath"
	"strconv"
)

const (
	pinnedRoot = "/sys/fs/bpf/otelauto"
)

var (
	PinnedMaps = []string{"ongoing_server_requests", "ongoing_goroutines"}
	PinnedRoot = filepath.Join(pinnedRoot, strconv.Itoa(os.Getpid()))
)
