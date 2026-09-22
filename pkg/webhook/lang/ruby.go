package lang

import (
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/prometheus/procfs"
)

type RubyVersion struct {
	Major int
	Minor int
}

var librubyRegex = regexp.MustCompile(`^libruby(?:-(\d+)\.(\d+))?\.so(?:\.(\d+)\.(\d+)(?:\.\d+)*)?$`)

func DetectRubyVersion(maps []*procfs.ProcMap) *RubyVersion {
	for _, m := range maps {
		if version := rubyVersion(filepath.Base(m.Pathname)); version != nil {
			return version
		}
	}
	return nil
}

func rubyVersion(library string) *RubyVersion {
	match := librubyRegex.FindStringSubmatch(library)
	if match == nil {
		return nil
	}
	major, minor := match[1], match[2]
	if major == "" {
		major, minor = match[3], match[4]
	}
	return parseRubyVersion(major, minor)
}

func parseRubyVersion(major, minor string) *RubyVersion {
	majorNumber, majorErr := strconv.Atoi(major)
	minorNumber, minorErr := strconv.Atoi(minor)
	if majorErr != nil || minorErr != nil {
		return nil
	}
	return &RubyVersion{Major: majorNumber, Minor: minorNumber}
}
