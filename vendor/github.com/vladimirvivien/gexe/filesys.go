package gexe

import (
	"os"

	"github.com/vladimirvivien/gexe/fs"
)

// PathExists returns true if path exists.
// All errors causes to return false.
func (e *Echo) PathExists(path string) bool {
	return fs.PathWithVars(path, e.vars).Exists()
}

// MkDir creates a directory at specified path with mode value.
// FSInfo contains information about the path or error if occured
func (e *Echo) MkDir(path string, mode os.FileMode) *fs.FSInfo {
	p := fs.PathWithVars(path, e.vars)
	return p.MkDir(mode)
}

// RmPath removes specified path (dir or file).
// Error is returned FSInfo.Err()
func (e *Echo) RmPath(path string) *fs.FSInfo {
	p := fs.PathWithVars(path, e.vars)
	return p.Remove()
}

// PathInfo
func (e *Echo) PathInfo(path string) *fs.FSInfo {
	return fs.PathWithVars(path, e.vars).Info()
}

// FileRead provides methods to read file content
//
// FileRead(path).Lines()
func (e *Echo) FileRead(path string) *fs.FileReader {
	return fs.PathWithVars(path, e.vars).Read()
}

// FileWrite provides methods to write content to provided path
//
// FileWrite(path).String("hello world")
func (e *Echo) FileWrite(path string) *fs.FileWriter {
	return fs.PathWithVars(path, e.vars).Write()
}

// FileAppend provides methods to append content to provided path
//
// FileAppend(path).String("hello world")
func (e *Echo) FileAppend(path string) *fs.FileWriter {
	return fs.PathWithVars(path, e.vars).Append()
}
