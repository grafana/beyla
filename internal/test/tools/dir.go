package tools

import (
	"os"
	"path"
	"path/filepath"
	"runtime"
)

// ProjectDir returns the path of the project's root folder
func ProjectDir() string {
	// Check for environment variable override (useful for pre-compiled binaries)
	if projectDir := os.Getenv("TEST_PROJECT_DIR"); projectDir != "" {
		return filepath.Clean(projectDir)
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("can't get runtime caller(0) file path")
	}
	thisDir := filepath.Dir(thisFile)
	var err error
	thisDir, err = filepath.Abs(thisDir)
	if err != nil {
		panic("can't get current file absolute path: " + err.Error())
	}

	// Move up until we find the project's root folder, which is the directory that
	// contains the "go.mod" and "go.sum" files.
	// It's important that this file is not placed in another subproject with its own "go.mod" and "go.sum"
	isProjectRoot := func(dir string) bool {
		for _, f := range []string{"go.mod", "go.sum"} {
			if _, err := os.Stat(path.Join(dir, f)); err != nil {
				return false
			}
		}
		return true
	}

	for i := 0; i < 50; i++ { // Limit directory traversal to prevent infinite loops
		if isProjectRoot(thisDir) {
			break
		}
		thisDir = filepath.Dir(thisDir)
	}

	return filepath.Clean(thisDir)
}
