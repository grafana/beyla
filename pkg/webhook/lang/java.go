package lang

import "strings"

// JavaAgent describes a -javaagent: directive found for a process.
type JavaAgent struct {
	// Source is where the directive was found: "cmdline" or the env var name.
	Source string
	// Arg is the matched argument starting with "-javaagent:".
	Arg string
}

// JavaOptionsEnvVars lists the environment variables the JVM consults for
// additional options, in the order we check them.
var JavaOptionsEnvVars = []string{
	"JAVA_TOOL_OPTIONS",
	"_JAVA_OPTIONS",
	"JDK_JAVA_OPTIONS",
	"IBM_JAVA_OPTIONS",
	"OPENJ9_JAVA_OPTIONS",
}

const javaAgentPrefix = "-javaagent:"

// FindJavaAgent scans process cmdline arguments and environment for a
// -javaagent: directive. cmdline is the process argv (e.g. the result of
// splitting /proc/<pid>/cmdline on NUL). env is the process environment as
// a name->value map. cmdline takes precedence over env vars; env vars are
// checked in the order of JavaOptionsEnvVars. Returns nil if none found.
func FindJavaAgent(cmdline []string, env map[string]string) *JavaAgent {
	if arg := findJavaAgentArg(cmdline); arg != "" {
		return &JavaAgent{Source: "cmdline", Arg: arg}
	}
	for _, name := range JavaOptionsEnvVars {
		val, ok := env[name]
		if !ok || val == "" {
			continue
		}
		if arg := findJavaAgentArg(parseJVMArgs(val)); arg != "" {
			return &JavaAgent{Source: name, Arg: arg}
		}
	}
	return nil
}

func findJavaAgentArg(args []string) string {
	for _, a := range args {
		if strings.HasPrefix(a, javaAgentPrefix) {
			return a
		}
	}
	return ""
}

// parseJVMArgs splits a JVM options string (JAVA_TOOL_OPTIONS, _JAVA_OPTIONS,
// etc.) into individual arguments using HotSpot's rules from
// Arguments::parse_options_buffer:
//   - tokens are separated by whitespace (space, tab, newline, carriage return)
//   - single or double quotes preserve whitespace within a token; quotes are
//     stripped from the output
//   - within a quoted run, a backslash escapes only the matching quote;
//     backslash is otherwise a literal character
//   - quotes may begin/end mid-token: foo"bar baz"qux is one token "foobar bazqux"
func parseJVMArgs(s string) []string {
	var args []string
	var cur strings.Builder
	inToken := false

	flush := func() {
		if inToken {
			args = append(args, cur.String())
			cur.Reset()
			inToken = false
		}
	}

	i := 0
	for i < len(s) {
		c := s[i]
		if isJVMSpace(c) {
			flush()
			i++
			continue
		}
		if c == '\'' || c == '"' {
			quote := c
			i++
			for i < len(s) && s[i] != quote {
				if s[i] == '\\' && i+1 < len(s) && s[i+1] == quote {
					i++
				}
				cur.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				i++
			}
			inToken = true
			continue
		}
		cur.WriteByte(c)
		inToken = true
		i++
	}
	flush()
	return args
}

func isJVMSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
