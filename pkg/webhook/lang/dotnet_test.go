package lang

import "testing"

func TestHasDotnetInstrumentation(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{
			name: "nil env",
			env:  nil,
			want: false,
		},
		{
			name: "unrelated otel config does not count",
			env: map[string]string{
				"OTEL_SERVICE_NAME": "checkout",
			},
			want: false,
		},
		{
			name: "empty known var does not count",
			env: map[string]string{
				"DOTNET_STARTUP_HOOKS": " \t\n",
			},
			want: false,
		},
		{
			name: "startup hooks count",
			env: map[string]string{
				"DOTNET_STARTUP_HOOKS": "/otel/net/OpenTelemetry.AutoInstrumentation.StartupHook.dll",
			},
			want: true,
		},
		{
			name: "coreclr profiling enabled counts",
			env: map[string]string{
				coreclrEnableProfilingEnvVar: "1",
			},
			want: true,
		},
		{
			name: "coreclr profiling trims whitespace",
			env: map[string]string{
				coreclrEnableProfilingEnvVar: " 1 ",
			},
			want: true,
		},
		{
			name: "coreclr profiling disabled does not count",
			env: map[string]string{
				coreclrEnableProfilingEnvVar: "0",
			},
			want: false,
		},
		{
			name: "coreclr profiling non-one value does not count",
			env: map[string]string{
				coreclrEnableProfilingEnvVar: "true",
			},
			want: false,
		},
		{
			name: "coreclr profiler path counts",
			env: map[string]string{
				"CORECLR_PROFILER_PATH": "/otel/linux-x64/OpenTelemetry.AutoInstrumentation.Native.so",
			},
			want: true,
		},
		{
			name: "dotnet auto home counts",
			env: map[string]string{
				"OTEL_DOTNET_AUTO_HOME": "/otel",
			},
			want: true,
		},
		{
			name: "additional deps count",
			env: map[string]string{
				"DOTNET_ADDITIONAL_DEPS": "/otel/AdditionalDeps",
			},
			want: true,
		},
		{
			name: "shared store counts",
			env: map[string]string{
				"DOTNET_SHARED_STORE": "/otel/store",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasDotnetInstrumentation(tt.env); got != tt.want {
				t.Fatalf("HasDotnetInstrumentation() = %v, want %v", got, tt.want)
			}
		})
	}
}
