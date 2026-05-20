package lang

import "testing"

func TestHasNodeJSAutoInstrumentation(t *testing.T) {
	tests := []struct {
		name    string
		cmdline []string
		env     map[string]string
		want    bool
	}{
		{
			name:    "no instrumentation",
			cmdline: []string{"node", "server.js"},
			env:     nil,
			want:    false,
		},
		{
			name:    "cmdline long require separate arg",
			cmdline: []string{"node", "--require", nodeAutoInstrumentationModule, "server.js"},
			env:     nil,
			want:    true,
		},
		{
			name:    "cmdline short require separate arg",
			cmdline: []string{"node", "-r", nodeAutoInstrumentationModule, "server.js"},
			env:     nil,
			want:    true,
		},
		{
			name:    "cmdline long require equals arg",
			cmdline: []string{"node", "--require=" + nodeAutoInstrumentationModule, "server.js"},
			env:     nil,
			want:    true,
		},
		{
			name:    "cmdline short require equals arg",
			cmdline: []string{"node", "-r=" + nodeAutoInstrumentationModule, "server.js"},
			env:     nil,
			want:    true,
		},
		{
			name:    "node options long require separate arg",
			cmdline: []string{"node", "server.js"},
			env: map[string]string{
				nodeOptionsEnvVar: "--require " + nodeAutoInstrumentationModule,
			},
			want: true,
		},
		{
			name:    "node options short require equals arg",
			cmdline: []string{"node", "server.js"},
			env: map[string]string{
				nodeOptionsEnvVar: "-r=" + nodeAutoInstrumentationModule,
			},
			want: true,
		},
		{
			name:    "other require module does not count",
			cmdline: []string{"node", "--require", "./instrumentation.js", "server.js"},
			env:     nil,
			want:    false,
		},
		{
			name:    "module without require flag does not count",
			cmdline: []string{"node", nodeAutoInstrumentationModule, "server.js"},
			env:     nil,
			want:    false,
		},
		{
			name:    "require flag without value does not count",
			cmdline: []string{"node", "--require"},
			env:     nil,
			want:    false,
		},
		{
			name:    "empty node options ignored",
			cmdline: []string{"node", "server.js"},
			env: map[string]string{
				nodeOptionsEnvVar: "",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasNodeJSAutoInstrumentation(tt.cmdline, tt.env); got != tt.want {
				t.Fatalf("HasNodeJSAutoInstrumentation() = %v, want %v", got, tt.want)
			}
		})
	}
}
