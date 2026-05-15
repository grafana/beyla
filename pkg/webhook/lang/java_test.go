package lang

import (
	"reflect"
	"testing"
)

func TestFindJavaAgent(t *testing.T) {
	tests := []struct {
		name    string
		cmdline []string
		env     map[string]string
		want    *JavaAgent
	}{
		{
			name:    "no agent",
			cmdline: []string{"java", "-jar", "app.jar"},
			env:     map[string]string{"JAVA_TOOL_OPTIONS": "-Xmx512m"},
			want:    nil,
		},
		{
			name:    "agent on cmdline",
			cmdline: []string{"java", "-javaagent:/otel/opentelemetry-javaagent.jar", "-jar", "app.jar"},
			env:     nil,
			want:    &JavaAgent{Source: "cmdline", Arg: "-javaagent:/otel/opentelemetry-javaagent.jar"},
		},
		{
			name:    "agent in java tool options",
			cmdline: []string{"java", "-jar", "app.jar"},
			env: map[string]string{
				"JAVA_TOOL_OPTIONS": "-Xmx512m -javaagent:/env-agent.jar -Dfoo=bar",
			},
			want: &JavaAgent{Source: "JAVA_TOOL_OPTIONS", Arg: "-javaagent:/env-agent.jar"},
		},
		{
			name:    "agent in quoted java tool options",
			cmdline: []string{"java", "-jar", "app.jar"},
			env: map[string]string{
				"JAVA_TOOL_OPTIONS": `-Xmx512m "-javaagent:/opt/otel agent/opentelemetry-javaagent.jar"`,
			},
			want: &JavaAgent{Source: "JAVA_TOOL_OPTIONS", Arg: "-javaagent:/opt/otel agent/opentelemetry-javaagent.jar"},
		},
		{
			name:    "env vars checked in declared order",
			cmdline: []string{"java", "-jar", "app.jar"},
			env: map[string]string{
				"_JAVA_OPTIONS":     "-javaagent:/second.jar",
				"JAVA_TOOL_OPTIONS": "-javaagent:/first.jar",
			},
			want: &JavaAgent{Source: "JAVA_TOOL_OPTIONS", Arg: "-javaagent:/first.jar"},
		},
		{
			name:    "empty option env is ignored",
			cmdline: []string{"java", "-jar", "app.jar"},
			env: map[string]string{
				"JAVA_TOOL_OPTIONS": "",
				"_JAVA_OPTIONS":     "-javaagent:/fallback.jar",
			},
			want: &JavaAgent{Source: "_JAVA_OPTIONS", Arg: "-javaagent:/fallback.jar"},
		},
		{
			name:    "javaagent without colon is ignored",
			cmdline: []string{"java", "-javaagent", "/agent.jar", "-jar", "app.jar"},
			env:     nil,
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindJavaAgent(tt.cmdline, tt.env)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("FindJavaAgent() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParseJVMArgs(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "splits whitespace",
			in:   " -Xmx512m\t-Dfoo=bar\n-javaagent:/agent.jar ",
			want: []string{"-Xmx512m", "-Dfoo=bar", "-javaagent:/agent.jar"},
		},
		{
			name: "preserves spaces inside double quotes",
			in:   `-Dname="checkout api" -jar app.jar`,
			want: []string{"-Dname=checkout api", "-jar", "app.jar"},
		},
		{
			name: "preserves spaces inside single quotes",
			in:   `-Dname='checkout api' -jar app.jar`,
			want: []string{"-Dname=checkout api", "-jar", "app.jar"},
		},
		{
			name: "quotes can appear mid token",
			in:   `-Dpath=/opt/"otel agent"/agent.jar`,
			want: []string{"-Dpath=/opt/otel agent/agent.jar"},
		},
		{
			name: "backslash escapes matching quote",
			in:   `"-Dmessage=hello \"otel\"" -jar app.jar`,
			want: []string{`-Dmessage=hello "otel"`, "-jar", "app.jar"},
		},
		{
			name: "backslash is literal outside matching quote escape",
			in:   `'-Dpath=C:\otel' "-Dother=C:\otel"`,
			want: []string{`-Dpath=C:\otel`, `-Dother=C:\otel`},
		},
		{
			name: "unterminated quote flushes current token",
			in:   `-Xmx512m "-Dname=checkout api`,
			want: []string{"-Xmx512m", "-Dname=checkout api"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseJVMArgs(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseJVMArgs(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}
