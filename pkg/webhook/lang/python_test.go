package lang

import (
	"reflect"
	"testing"

	"github.com/prometheus/procfs"
)

func TestDetectPythonVersion(t *testing.T) {
	tests := []struct {
		name string
		maps []*procfs.ProcMap
		want *PythonVersion
	}{
		{
			name: "nil maps",
			maps: nil,
			want: nil,
		},
		{
			name: "no libpython",
			maps: []*procfs.ProcMap{
				{Pathname: "/usr/bin/python3.11"},
				{Pathname: "/lib/x86_64-linux-gnu/libc.so.6"},
			},
			want: nil,
		},
		{
			name: "detects major and minor from versioned shared library",
			maps: []*procfs.ProcMap{
				{Pathname: "/usr/lib/x86_64-linux-gnu/libpython3.11.so.1.0"},
			},
			want: &PythonVersion{Major: 3, Minor: 11},
		},
		{
			name: "ignores libpython3.so without minor",
			maps: []*procfs.ProcMap{
				{Pathname: "/usr/lib/libpython3.so"},
			},
			want: nil,
		},
		{
			name: "ignores libpython2.so without minor",
			maps: []*procfs.ProcMap{
				{Pathname: "/usr/lib/libpython2.so"},
			},
			want: nil,
		},
		{
			name: "skips version-less symlink and finds versioned libpython",
			maps: []*procfs.ProcMap{
				{Pathname: "/usr/lib/libpython3.so"},
				{Pathname: "/usr/lib/libpython3.11.so.1.0"},
			},
			want: &PythonVersion{Major: 3, Minor: 11},
		},
		{
			name: "detects python two version",
			maps: []*procfs.ProcMap{
				{Pathname: "/opt/python/lib/libpython2.7.so.1.0"},
			},
			want: &PythonVersion{Major: 2, Minor: 7},
		},
		{
			name: "uses basename only",
			maps: []*procfs.ProcMap{
				{Pathname: "/tmp/libpython3.12.so.1.0.deleted/libc.so.6"},
				{Pathname: "/opt/runtime/lib/libpython3.12.so.1.0"},
			},
			want: &PythonVersion{Major: 3, Minor: 12},
		},
		{
			name: "returns first matching libpython",
			maps: []*procfs.ProcMap{
				{Pathname: "/usr/lib/libpython3.10.so.1.0"},
				{Pathname: "/usr/lib/libpython3.11.so.1.0"},
			},
			want: &PythonVersion{Major: 3, Minor: 10},
		},
		{
			name: "non shared library extension ignored",
			maps: []*procfs.ProcMap{
				{Pathname: "/usr/lib/libpython3.11.a"},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectPythonVersion(tt.maps); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("DetectPythonVersion() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
