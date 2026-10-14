// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"debug/elf"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/hashicorp/go-version"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// https://nodejs.org/api/async_context.html — "Added in: v13.10.0, v12.17.0"
var (
	minInjectableVersion = version.Must(version.NewVersion("12.17.0"))
	node13Series         = version.Must(version.NewVersion("13.0.0"))
	node13Backport       = version.Must(version.NewVersion("13.10.0"))
)

// https://nodejs.org/en/blog/release/v14.0.0 — "Enables Nullish Coalescing by default"
var minManualSpansVersion = version.Must(version.NewVersion("14.0.0"))

func supportsManualSpans(nodeVersion *version.Version) bool {
	return nodeVersion.GreaterThanOrEqual(minManualSpansVersion)
}

func supportsAsyncLocalStorage(nodeVersion *version.Version) bool {
	if nodeVersion.LessThan(minInjectableVersion) {
		return false
	}

	return nodeVersion.LessThan(node13Series) || nodeVersion.GreaterThanOrEqual(node13Backport)
}

// Node.js builds its /json/version reply from the literal "node.js/" NODE_VERSION
// (src/inspector_socket_server.cc), so the concatenated string sits in .rodata and
// survives stripping. The NUL delimiters keep the match to a whole string in the
// pool rather than a suffix of a longer one, such as myapp-node.js/v1.2.3, and
// bounded components keep versionLiteralMax finite.
var nodeVersionPattern = regexp.MustCompile(`\x00node\.js/v(\d{1,3}\.\d{1,3}\.\d{1,3})\x00`)

// versionLiteralMax is the longest string nodeVersionPattern can match, so a
// chunked scan knows how much to carry across a read boundary.
const versionLiteralMax = len("\x00node.js/v") + len("000.000.000\x00")

const rodataChunkSize = 1 << 20

// Distribution packages link the runtime as a library and leave the executable
// a launcher, which carries no version of its own. Discovery types those as
// Node.js too (pkg/internal/procs/proclang.go), so reading only the executable
// would refuse every distribution-packaged runtime.
const libNodeName = "libnode.so"

func nodeVersionFromProcess(target InjectionTarget, elfFile *elf.File) (*version.Version, bool) {
	if nodeVersion, ok := nodeVersionFromELF(elfFile); ok {
		return nodeVersion, true
	}

	return nodeVersionFromLibNode(target)
}

func nodeVersionFromLibNode(target InjectionTarget) (*version.Version, bool) {
	maps, err := procs.FindLibMaps(target.Pid)
	if err != nil {
		return nil, false
	}

	libNode := procs.LibPath(libNodeName, maps)
	if libNode == nil {
		return nil, false
	}

	// map_files resolves the mapping inside whatever mount namespace the process
	// runs in, and the pinned handle keeps a recycled pid from answering for it
	lib, err := target.Process.Open(
		fmt.Sprintf("map_files/%x-%x", libNode.StartAddr, libNode.EndAddr), os.O_RDONLY)
	if err != nil {
		return nil, false
	}
	defer lib.Close()

	libFile, err := elf.NewFile(lib)
	if err != nil {
		return nil, false
	}
	defer libFile.Close()

	return nodeVersionFromELF(libFile)
}

func nodeVersionFromELF(elfFile *elf.File) (*version.Version, bool) {
	if elfFile == nil {
		return nil, false
	}

	rodata := elfFile.Section(".rodata")
	if rodata == nil || rodata.Type == elf.SHT_NOBITS {
		return nil, false
	}

	return scanNodeVersion(rodata.Open(), rodataChunkSize)
}

func scanNodeVersion(r io.Reader, chunkSize int) (*version.Version, bool) {
	// below one the carry fills the buffer, every read is empty and the loop
	// never advances
	buf := make([]byte, max(chunkSize, 1)+versionLiteralMax)
	held := 0

	for {
		n, err := io.ReadFull(r, buf[held:])
		end := held + n

		if nodeVersion, ok := nodeVersionFrom(buf[:end]); ok {
			return nodeVersion, true
		}

		if err != nil {
			return nil, false
		}

		held = min(versionLiteralMax, end)
		copy(buf, buf[end-held:end])
	}
}

func nodeVersionFrom(rodata []byte) (*version.Version, bool) {
	match := nodeVersionPattern.FindSubmatch(rodata)
	if match == nil {
		return nil, false
	}

	nodeVersion, err := version.NewVersion(string(match[1]))
	if err != nil {
		return nil, false
	}

	return nodeVersion, true
}
