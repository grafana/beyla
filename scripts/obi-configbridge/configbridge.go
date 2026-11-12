// Package configbridge re-exports OBI's config v2 loader and file watcher.
//
// Those APIs live in go.opentelemetry.io/obi/cmd/obi/internal and
// go.opentelemetry.io/obi/internal/config.
package configbridge

import (
	"context"
	"errors"
	"io"

	"go.opentelemetry.io/obi/cmd/obi/internal/configcmd"
	"go.opentelemetry.io/obi/cmd/obi/internal/configload"
	"go.opentelemetry.io/obi/cmd/obi/internal/configwatch"
	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/obi"
)

// RunConfigCommand runs OBI's `config validate` and `config migrate` commands.
// It reports whether args selected the config command group, and the exit code
// to use when it did.
func RunConfigCommand(args []string, stdout, stderr io.Writer) (bool, int) {
	return configcmd.MaybeRun(args, stdout, stderr)
}

// LoadV2 converts a standalone config v2 document into a runtime config.
func LoadV2(data []byte) (*obi.Config, error) {
	return configload.LoadV2(data)
}

// IsNotV2 reports whether err means the document is not config v2.
// Other load errors must not be treated as a v1 document.
func IsNotV2(err error) bool {
	var notV2 *schema.NotV2Error
	return errors.As(err, &notV2)
}

// Watch polls path and applies discovery-criteria refreshes the same way OBI's
// cmd/obi process does.
func Watch(ctx context.Context, path string, initial []byte, refresh func(context.Context, *obi.Config) error) {
	configwatch.Watch(ctx, path, initial, refresh)
}
