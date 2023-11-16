package offsets

const GoStdLib = "go"

// InputLibs key: name of the library, or "go" for the Go standard library
type InputLibs map[string]LibQuery

type LibQuery struct {
	// Inspect provides the path to a Go source file that will be compiled and
	// will inspect the offsets from the generated executable. If not set, it will
	// analise the "go" executable for Go stdlib functions, and for third-party libraries,
	// it will analyse an empty main file that forces the inclusion of the inspected library.
	Inspect string `json:"inspect"`

	// Branch will force downloading the branch name specified here, ignoring the
	// Versions field. This is useful for source repositories without release tags.
	Branch string `json:"branch"`

	// Packages overrides the packages that need to be downloaded for inspection. If empty, it will
	// download the root package (same as the library URL). Setting this value is useful for libraries that do
	// not have any root package and the download would fail (e.g. google.golang.org/genproto)
	Packages []string `json:"packages"`

	// Versions constraint. E.g. ">= 1.12" will only download versions
	// larger or equal to 1.12
	Versions string `json:"versions"`

	// Fields key: qualified name of the struct.
	// Examples: net/http.Request, google.golang.org/grpc/internal/transport.Stream
	// Value: list of case-sensitive name of the fields whose offsets we want to retrieve
	Fields map[string][]string
}
