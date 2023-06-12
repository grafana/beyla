package httpfltr

/*
   #cgo CFLAGS: -D_GNU_SOURCE
   #cgo LDFLAGS: -ldl

   #include <stdlib.h>
   #include <dlfcn.h>
*/
import "C"

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/exp/slog"
)

func findNamespace(pid int32) (uint32, error) {
	pidPath := fmt.Sprintf("/proc/%d/ns/pid", pid)
	f, err := os.Open(pidPath)

	if err != nil {
		return 0, fmt.Errorf("failed to open(/proc/%d/ns/pid): %w", pid, err)
	}

	defer f.Close()

	// read the value of the symbolic link
	buf := make([]byte, syscall.PathMax)
	n, err := syscall.Readlink(pidPath, buf)
	if err != nil {
		return 0, fmt.Errorf("failed to read symlink(/proc/%d/ns/pid): %w", pid, err)
	}

	logger := slog.With("component", "httpfltr.Tracer")

	nsPid := string(buf[:n])
	// extract u32 from the format pid:[nnnnn]
	start := strings.LastIndex(nsPid, "[")
	end := strings.LastIndex(nsPid, "]")

	logger.Info("Found namespace", "nsPid", nsPid)

	if start >= 0 && end >= 0 && end > start {
		npid, err := strconv.ParseUint(string(buf[start+1:end]), 10, 32)

		if err != nil {
			return 0, fmt.Errorf("failed to parse ns pid %w", err)
		}

		return uint32(npid), nil
	}

	return 0, fmt.Errorf("couldn't find ns pid in the symlink [%s]", nsPid)
}

func findSharedLib(lib string) (string, error) {
	libname := C.CString(lib)
	defer C.free(unsafe.Pointer(libname))

	handle := C.dlopen(libname, C.RTLD_NOW)
	if handle == nil {
		return "", fmt.Errorf("failed to load library: %s", C.GoString(C.dlerror()))
	}
	defer C.dlclose(handle)

	sslRead := C.CString("SSL_read")
	defer C.free(unsafe.Pointer(sslRead))
	addr := C.dlsym(handle, sslRead)
	if addr == nil {
		return "", fmt.Errorf("failed to find SSL_read: %s", C.GoString(C.dlerror()))
	}

	var info C.Dl_info
	if C.dladdr(addr, &info) == 0 {
		return "", fmt.Errorf("failed to get symbol information: %s", C.GoString(C.dlerror()))
	}

	return C.GoString(info.dli_fname), nil
}
