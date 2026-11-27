// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package rustexec identifies Rust compiler builds in native executables.
package rustexec // import "go.opentelemetry.io/obi/internal/rustexec"

import (
	"debug/elf"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

type Profile struct {
	Arch           string
	Rustc          string
	CompilerCommit string `json:",omitempty"`
}

type Database struct {
	Profiles []Profile `json:"profiles"`
}

type Build struct {
	Arch           string
	Rustc          string
	CompilerCommit string
}

var (
	rustCompilerVersion = regexp.MustCompile(`rustc version ([0-9]+\.[0-9]+\.[0-9]+) \(`)
	rustCompilerCommit  = regexp.MustCompile(`[/\\]rustc[/\\]([0-9a-f]{40})[/\\]`)
)

func ReadBuild(f *elf.File) (Build, error) {
	var b Build
	switch f.Machine {
	case elf.EM_X86_64:
		b.Arch = "amd64"
	case elf.EM_AARCH64:
		b.Arch = "arm64"
	default:
		return b, errors.New("unsupported Rust ELF architecture")
	}

	for _, section := range f.Sections {
		if section.Name != ".comment" && !strings.HasPrefix(section.Name, ".rodata") {
			continue
		}

		data, err := section.Data()
		if err != nil {
			return b, err
		}

		if version := rustCompilerVersion.FindSubmatch(data); len(version) > 0 {
			b.Rustc = string(version[1])
		}

		if commit := rustCompilerCommit.FindSubmatch(data); len(commit) > 0 {
			b.CompilerCommit = string(commit[1])
		}
	}

	return b, nil
}

var ErrUnsupportedCompiler = errors.New("unsupported Rust compiler")

// CheckCompiler checks whether the database supports the build's stable rustc minor version on its architecture.
func (d Database) CheckCompiler(build Build) error {
	build = d.InferBuild(build)
	if build.Rustc == "" {
		return fmt.Errorf("%w: could not identify rustc version on %s", ErrUnsupportedCompiler, build.Arch)
	}

	version := "v" + build.Rustc
	if minor := semver.MajorMinor(version); minor != "" && semver.Prerelease(version) == "" {
		for _, profile := range d.Profiles {
			if profile.Arch == build.Arch && semver.MajorMinor("v"+profile.Rustc) == minor {
				return nil
			}
		}
	}
	return fmt.Errorf("%w %q on %s", ErrUnsupportedCompiler, build.Rustc, build.Arch)
}

// InferBuild fills in a compiler version the binary's comment section omits.
// Toolchain builds share one standard-library commit, so its source paths
// identify the compiler of any binary built with that toolchain.
func (d Database) InferBuild(build Build) Build {
	if build.Rustc != "" || build.CompilerCommit == "" {
		return build
	}

	for _, profile := range d.Profiles {
		if profile.Arch == build.Arch && profile.CompilerCommit == build.CompilerCommit {
			build.Rustc = profile.Rustc
			break
		}
	}

	return build
}
