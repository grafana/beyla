// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package offsets

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/hashicorp/go-version"

	"github.com/grafana/go-offsets-tracker/pkg/versions"
)

type Track struct {
	// Data key: struct name, which includes the library name in external libraries
	Data map[string]Struct `json:"data"`
}

// Struct key: field name
type Struct map[string]Field

// Field offests must be sorted from higher to lower semantic version
type Field struct {
	// Versions range that are tracked for this given field
	Versions VersionInfo `json:"versions"`
	Offsets  []Versioned `json:"offsets"`
}

type VersionInfo struct {
	Oldest string `json:"oldest"`
	Newest string `json:"newest"`
}

type Versioned struct {
	Offset uint64 `json:"offset"`
	Since  string `json:"since"`
}

func Open(file string) (*Track, error) {
	if f, err := os.Open(file); err != nil {
		return nil, fmt.Errorf("opening offsets file: %w", err)
	} else {
		return Read(f)
	}
}

func Read(in io.Reader) (*Track, error) {
	offsetsFile, err := io.ReadAll(in)
	if err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}
	offsets := Track{}
	if err := json.Unmarshal(offsetsFile, &offsets); err != nil {
		return nil, fmt.Errorf("unmarshaling file contents: %w", err)
	}
	// The search algorithm assumes that all the fields are sorted from older
	// to newer version. So in case the file is disordered, we sort them here
	for _, s := range offsets.Data {
		for _, f := range s {
			sort.Slice(f.Offsets, func(i, j int) bool {
				return versions.MustParse(f.Offsets[i].Since).
					LessThan(versions.MustParse(f.Offsets[j].Since))
			})
		}
	}
	return &offsets, nil
}

// Find the offset of a field struct name, for a given lib version
func (to *Track) Find(structName, fieldName, libVersion string) (uint64, bool) {
	strct, ok := to.Data[structName]
	if !ok {
		return 0, false
	}
	field, ok := strct[fieldName]
	if !ok {
		return 0, false
	}
	return field.GetOffset(libVersion)
}

// GetOffset assumes that the fields offsets list is sorted from older to newer version
func (field *Field) GetOffset(libVersion string) (uint64, bool) {
	libVersion = versions.CleanVersion(libVersion)
	target, err := version.NewVersion(libVersion)
	if err != nil {
		// shouldn't happen unless a bug in our code/files
		panic(err.Error())
	}
	// Search from the newest version (last in the slice)
	for o := len(field.Offsets) - 1; o >= 0; o-- {
		od := &field.Offsets[o]
		fieldVersion, err := version.NewVersion(od.Since)
		if err != nil {
			// shouldn't happen unless a bug in our code
			panic(err.Error())
		}
		if target.Compare(fieldVersion) >= 0 {
			// if target version is larger or equal than lib version:
			// we certainly know that it is the most recent tracked offset
			// matching the target libVersion
			return od.Offset, true
		}
	}

	return 0, false
}
