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

	// Versions constraint. E.g. ">= 1.12" will only download versions
	// larger or equal to 1.12
	Versions string `json:"versions"`

	// Fields key: qualified name of the struct.
	// Examples: net/http.Request, google.golang.org/grpc/internal/transport.Stream
	// Value: list of case-sensitive name of the fields whose offsets we want to retrieve
	Fields map[string][]string
}
