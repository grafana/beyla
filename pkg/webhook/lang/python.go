package lang

import (
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/prometheus/procfs"
)

// PythonVersion holds the major.minor version of a Python interpreter
// detected from a dynamically-linked libpython in a process's memory maps.
type PythonVersion struct {
	Major int
	Minor int
}

// libpythonRegex matches shared-library basenames of the form:
//
//	libpython2.7.so.1.0, libpython3.11.so.1.0
//
// Libraries without an explicit minor version (libpython3.so, libpython2.so)
// are intentionally excluded because they don't carry enough information.
var libpythonRegex = regexp.MustCompile(`^libpython(\d+)\.(\d+)\.so(?:\.[\d.]+)?$`)

// DetectPythonVersion scans process memory maps for a dynamically-linked
// libpython and returns its major.minor version. Returns nil if no qualifying
// libpython is found (e.g. the interpreter is statically linked, this is not
// a Python process, or only a version-less libpython.so symlink is mapped).
func DetectPythonVersion(maps []*procfs.ProcMap) *PythonVersion {
	for _, m := range maps {
		match := libpythonRegex.FindStringSubmatch(filepath.Base(m.Pathname))
		if match == nil {
			continue
		}
		major, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		minor, err := strconv.Atoi(match[2])
		if err != nil {
			continue
		}
		return &PythonVersion{Major: major, Minor: minor}
	}
	return nil
}
