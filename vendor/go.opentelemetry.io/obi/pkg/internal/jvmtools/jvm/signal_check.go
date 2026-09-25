// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvm // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/jvm"

import (
	"bytes"
	"context"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

const sigquit = unix.SIGQUIT

// attachWait bounds how long to wait for HotSpot to install its SIGQUIT handler
// in Threads::create_vm, so a process discovered as soon as libjvm is mapped is
// not refused for a condition that clears.
const attachWait = 2 * time.Second

const (
	attachDisablingOption = "-XX:+DisableAttachMechanism"
	attachEnablingOption  = "-XX:-DisableAttachMechanism"
)

// optionVariablesBeforeCommandLine and optionVariablesAfterCommandLine are the
// environment variables the java launcher folds into the VM options, split
// around the command line by the order HotSpot applies them. Each is expanded by
// the launcher after exec, so none of them reaches the command line itself.
var (
	optionVariablesBeforeCommandLine = []string{"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS"}
	optionVariablesAfterCommandLine  = []string{"_JAVA_OPTIONS"}
)

// valueOptions take their value as the following argument, which must not be
// mistaken for the main class that ends the VM options.
var valueOptions = []string{
	"-cp", "-classpath", "--class-path",
	"-p", "--module-path", "--upgrade-module-path",
	"--add-modules", "--limit-modules",
	"--add-opens", "--add-exports", "--add-reads",
	"--patch-module", "--enable-native-access",
	"--source", "--describe-module", "-d",
}

// programOptions name the program to run, so the VM options end after their
// value and everything past it belongs to the application.
var programOptions = []string{"-jar", "-m", "--module"}

// openJ9Library is mapped by every OpenJ9 VM, next to the libjvm.so redirector
// that gets it typed as Java.
const openJ9Library = "/libj9vm"

const (
	refusalOpenJ9 = "the process is an OpenJ9 VM whose attach listener is not running: " +
		"OpenJ9 attaches without a signal, so SIGQUIT would only write a javacore"
	refusalSignalIsFatal = "SIGQUIT is still neither caught nor ignored after " +
		"waiting for the runtime to install its handler, so it would terminate the process. " +
		"A JVM that took longer than that to start is not retried"
	refusalDispositionUnknown = "the process caught and ignored signal sets could not be read"
	refusalAttachDisabled     = "the JVM runs with -XX:+DisableAttachMechanism"
)

// attachRefusal reports why the dynamic attach handshake is withheld, or an
// empty reason when SIGQUIT is safe to send and the JVM will act on it.
//
// HotSpot reserves SIGQUIT and rejects an application-level handler for it, so
// a JVM either answers the handshake or writes a thread dump to its own stdout.
// Neither is wanted from a target that cannot complete the handshake.
func attachRefusal(ctx context.Context, process *procs.ProcessHandle) string {
	// An OpenJ9 VM with its attach listener running is recognized earlier and
	// never reaches this path, so one that does has attach off or not yet up.
	if isOpenJ9(process) {
		return refusalOpenJ9
	}

	if attachDisabled(process) {
		return refusalAttachDisabled
	}

	switch process.AwaitSignalDisposition(ctx, sigquit, attachWait) {
	case procs.SignalDispositionFatal:
		return refusalSignalIsFatal
	case procs.SignalDispositionUnknown:
		return refusalDispositionUnknown
	case procs.SignalDispositionHandled:
	}

	return ""
}

// isOpenJ9 reports whether the process runs an OpenJ9 VM, read through the
// pinned handle. An unreadable map says nothing either way.
func isOpenJ9(process *procs.ProcessHandle) bool {
	maps, err := readProcFile(process, "maps")
	if err != nil {
		return false
	}

	return mapsOpenJ9(maps)
}

func mapsOpenJ9(maps []byte) bool {
	return bytes.Contains(maps, []byte(openJ9Library))
}

// attachDisabled reports whether the JVM was launched with the attach mechanism
// off, applying the option sources in the order HotSpot does so that a later
// source turning it back on is honored.
//
// A flags file is not covered: the cost of missing one is a thread dump, not a
// terminated process.
func attachDisabled(process *procs.ProcessHandle) bool {
	// A source that cannot be read contributes nothing rather than deciding the
	// answer: a process that is already gone is refused by the disposition check
	// on its own merits, not reported as having disabled anything.
	environ, _ := readProcFile(process, "environ")
	commandLine, _ := readProcFile(process, "cmdline")

	disabled := false

	apply := func(options [][]byte) {
		if setting, found := lastAttachSetting(options); found {
			disabled = setting
		}
	}

	for _, variable := range optionVariablesBeforeCommandLine {
		apply(optionWords(environValue(environ, variable)))
	}

	apply(vmOptions(commandLine))

	for _, variable := range optionVariablesAfterCommandLine {
		apply(optionWords(environValue(environ, variable)))
	}

	return disabled
}

// vmOptions returns the arguments HotSpot parses as VM options, which end at
// the program the launcher was asked to run: everything from the main class, or
// from the argument after -jar, belongs to the application. A launcher handing
// the flag to a child JVM therefore does not read as the flag of this one.
func vmOptions(commandLine []byte) [][]byte {
	arguments := splitArguments(commandLine)
	if len(arguments) == 0 {
		return nil
	}

	options := make([][]byte, 0, len(arguments))

	for i := 1; i < len(arguments); i++ {
		argument := string(arguments[i])

		if !bytes.HasPrefix(arguments[i], []byte("-")) {
			break
		}

		options = append(options, arguments[i])

		name, _, hasValue := strings.Cut(argument, "=")

		switch {
		case slices.Contains(programOptions, name):
			return options
		case !hasValue && slices.Contains(valueOptions, argument):
			i++
		}
	}

	return options
}

// lastAttachSetting reports the sense of the final -XX:±DisableAttachMechanism
// among options, and whether one was present at all. Each option is matched
// whole, so an argument that merely contains the flag is not one.
func lastAttachSetting(options [][]byte) (disabled, found bool) {
	for _, option := range options {
		switch string(option) {
		case attachDisablingOption:
			disabled, found = true, true
		case attachEnablingOption:
			disabled, found = false, true
		}
	}

	return disabled, found
}

// environValue returns the value of name in a NUL-separated environment block.
func environValue(environ []byte, name string) []byte {
	prefix := []byte(name + "=")

	for entry := range bytes.SplitSeq(environ, []byte{0}) {
		if value, ok := bytes.CutPrefix(entry, prefix); ok {
			return value
		}
	}

	return nil
}

// optionWords splits an option variable the way the launcher does, on any run
// of whitespace. Quoting is not honored, so a quoted flag reads as absent,
// which withholds nothing and costs at most a thread dump.
func optionWords(value []byte) [][]byte {
	return bytes.Fields(value)
}

func splitArguments(commandLine []byte) [][]byte {
	arguments := bytes.Split(bytes.TrimSuffix(commandLine, []byte{0}), []byte{0})
	if len(arguments) == 1 && len(arguments[0]) == 0 {
		return nil
	}

	return arguments
}

func readProcFile(process *procs.ProcessHandle, name string) ([]byte, error) {
	f, err := process.Open(name, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
}
