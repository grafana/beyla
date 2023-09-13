package tools

import (
	"path"
	"path/filepath"
	"runtime"
)

// ProjectDir returns the path of the project's root folder
func ProjectDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("can't get runtime caller(0) file path")
	}
	thisDir := filepath.Dir(thisFile)

	// If we move this file path, this probaly will need to change
	// Unit tests are provided to avoid a file move to break other tests
	projectDirFromHere := path.Join(thisDir, "..", "..")

	abs, err := filepath.Abs(projectDirFromHere)
	if err != nil {
		panic("can't get project's absolute file: " + err.Error())
	}
	return filepath.Clean(abs)
}
