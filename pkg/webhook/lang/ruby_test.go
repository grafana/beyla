package lang

import (
	"reflect"
	"testing"

	"github.com/prometheus/procfs"
)

func TestDetectRubyVersion(t *testing.T) {
	tests := []struct {
		name string
		maps []*procfs.ProcMap
		want *RubyVersion
	}{
		{name: "nil maps"},
		{
			name: "version after library name",
			maps: []*procfs.ProcMap{{Pathname: "/usr/lib/libruby-3.3.so.3.3"}},
			want: &RubyVersion{Major: 3, Minor: 3},
		},
		{
			name: "version in soname",
			maps: []*procfs.ProcMap{{Pathname: "/usr/local/lib/libruby.so.3.4.1"}},
			want: &RubyVersion{Major: 3, Minor: 4},
		},
		{
			name: "unversioned library",
			maps: []*procfs.ProcMap{{Pathname: "/usr/lib/libruby.so"}},
		},
		{
			name: "major only soname",
			maps: []*procfs.ProcMap{{Pathname: "/usr/lib/libruby.so.3"}},
		},
		{
			name: "unrelated path",
			maps: []*procfs.ProcMap{{Pathname: "/tmp/libruby.so.3.2/libc.so.6"}},
		},
		{
			name: "first versioned library",
			maps: []*procfs.ProcMap{
				{Pathname: "/usr/lib/libruby.so"},
				{Pathname: "/usr/lib/libruby-3.2.so.3.2.0"},
				{Pathname: "/usr/lib/libruby-3.3.so.3.3.0"},
			},
			want: &RubyVersion{Major: 3, Minor: 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectRubyVersion(tt.maps); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("DetectRubyVersion() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
