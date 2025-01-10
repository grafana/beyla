package gexe

import (
	"os"

	"github.com/vladimirvivien/gexe/exec"
	"github.com/vladimirvivien/gexe/fs"
	"github.com/vladimirvivien/gexe/http"
	"github.com/vladimirvivien/gexe/prog"
	"github.com/vladimirvivien/gexe/str"
	"github.com/vladimirvivien/gexe/vars"
)

// Variables returns variable map for DefaultEcho session
func Variables() *vars.Variables {
	return DefaultEcho.Variables()
}

// Envs declares environment variables using
// a multi-line space-separated list:
//
//	Envs("GOOS=linux GOARCH=amd64")
//
// Environment vars can be used in string values
// using Eval("building for os=$GOOS")
func Envs(val string) *Echo {
	return DefaultEcho.Envs(val)
}

// SetEnv sets a process environment variable.
func SetEnv(name, value string) *Echo {
	return DefaultEcho.SetEnv(name, value)
}

// Vars declares session-scope variables using
// a multi-line space-separated list:
//
//	Envs("foo=bar platform=amd64")
//
// Session vars can be used in string values
// using Eval("My foo=$foo").
//
// Note that session vars are only available
// for the running process.
func Vars(val string) *Echo {
	return DefaultEcho.Vars(val)
}

// SetVar declares a session variable.
func SetVar(name, value string) *Echo {
	return DefaultEcho.SetVar(name, value)
}

// Val retrieves a session or environment variable
func Val(name string) string {
	return DefaultEcho.Val(name)
}

// Eval returns the string str with its content expanded
// with variable values i.e. Eval("I am $HOME") returns
// "I am </user/home/path>"
func Eval(str string) string {
	return DefaultEcho.Eval(str)
}

// NewProc setups a new process with specified command cmdStr and returns immediately
// without starting. Information about the running process is stored in *exec.Proc.
func NewProc(cmdStr string) *exec.Proc {
	return DefaultEcho.NewProc(cmdStr)
}

// StartProc executes the command in cmdStr and returns immediately
// without waiting. Information about the running process is stored in *exec.Proc.
func StartProc(cmdStr string) *exec.Proc {
	return DefaultEcho.StartProc(cmdStr)
}

// RunProc executes command in cmdStr and waits for the result.
// It returns a *Proc with information about the executed process.
func RunProc(cmdStr string) *exec.Proc {
	return DefaultEcho.RunProc(cmdStr)
}

// Run executes cmdStr, waits, and returns the result as a string.
func Run(cmdStr string) string {
	return DefaultEcho.Run(cmdStr)
}

// Runout executes command cmdStr and prints out the result
func Runout(cmdStr string) {
	DefaultEcho.Runout(cmdStr)
}

// Commands returns a *exe.CommandBuilder to build a multi-command execution flow.
func Commands(cmdStrs ...string) *exec.CommandBuilder {
	return DefaultEcho.Commands(cmdStrs...)
}

// StartAll starts the exection of each command sequentially and
// does not wait for their completion.
func StartAll(cmdStrs ...string) *exec.CommandResult {
	return DefaultEcho.StartAll(cmdStrs...)
}

// RunAll executes each command, in cmdStrs, successively and wait for their
// completion.
func RunAll(cmdStrs ...string) *exec.CommandResult {
	return DefaultEcho.RunAll(cmdStrs...)
}

// StartConcur starts the exection of each command concurrently and
// does not wait for their completion.
func StartConcur(cmdStrs ...string) *exec.CommandResult {
	return DefaultEcho.StartConcur(cmdStrs...)
}

// RunConcur executes each command, in cmdStrs, concurrently and waits
// their completion.
func RunConcur(cmdStrs ...string) *exec.CommandResult {
	return DefaultEcho.RunConcur(cmdStrs...)
}

// Pipe executes each command, in cmdStrs, by piping the result
// of the previous command as input to the next command until done.
func Pipe(cmdStrs ...string) *exec.PipedCommandResult {
	return DefaultEcho.Pipe(cmdStrs...)
}

// PathExists returns true if specified path exists.
// Any error will cause it to return false.
func PathExists(path string) bool {
	return DefaultEcho.PathExists(path)
}

// PathInfo returns information for specified path (i.e. size, etc)
func PathInfo(path string) *fs.FSInfo {
	return DefaultEcho.PathInfo(path)
}

// MkDirs creates one or more directories along the specified path
func MkDirs(path string, mode os.FileMode) *fs.FSInfo {
	return DefaultEcho.MkDir(path, mode)
}

// MkDir creates a directory with default mode 0744
func MkDir(path string) *fs.FSInfo {
	return DefaultEcho.MkDir(path, 0744)
}

// RmPath removes files or directories along specified path
func RmPath(path string) *fs.FSInfo {
	return DefaultEcho.RmPath(path)
}

// FileRead provides methods to read file content from path
func FileRead(path string) *fs.FileReader {
	return DefaultEcho.FileRead(path)
}

// FileWrite provides methods to write file content to path
func FileWrite(path string) *fs.FileWriter {
	return DefaultEcho.FileWrite(path)
}

// GetUrl creates a *http.ResourceReader to retrieve HTTP content
func GetUrl(url string) *http.ResourceReader {
	return DefaultEcho.Get(url)
}

// PostUrl creates a *http.ResourceWriter to write content to an HTTP server
func PostUrl(url string) *http.ResourceWriter {
	return DefaultEcho.Post(url)
}

// Prog returns program information via *prog.Info
func Prog() *prog.Info {
	return DefaultEcho.Prog()
}

// ProgAvail returns the full path of the program if available.
func ProgAvail(program string) string {
	return DefaultEcho.ProgAvail(program)
}

// Workdir returns the current program's working directory
func Workdir() string {
	return DefaultEcho.Workdir()
}

// AddExecPath adds an executable path to PATH
func AddExecPath(execPath string) {
	DefaultEcho.AddExecPath(execPath)
}

func String(s string) *str.Str {
	return DefaultEcho.String(s)
}
