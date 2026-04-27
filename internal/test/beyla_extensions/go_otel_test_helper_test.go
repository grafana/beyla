//go:build ignore

// buildDockerImageWithContext helper for go_otel integration tests.
// This file is copied to internal/testgenerated/integration/ by generate-obi-tests.sh

package integration

import (
	"context"
	"fmt"
	"io"

	"github.com/moby/moby/client"
)

// buildDockerImageWithContext builds a Docker image using contextDir as the
// Docker build context root, rather than pathRoot (the Beyla repo root).
// Use this for images whose Dockerfile COPY instructions are relative to a
// directory other than the Beyla repo root — e.g. .obi-src for go_otel.
func buildDockerImageWithContext(ctx context.Context, output io.Writer, tag, contextDir, dockerfile string) error {
	buildContext, err := createBuildContext(contextDir)
	if err != nil {
		return err
	}
	defer func() {
		_ = buildContext.Close()
	}()

	result, err := dockerPool.Client().ImageBuild(ctx, buildContext, client.ImageBuildOptions{
		Tags:       []string{tag},
		Dockerfile: dockerfile,
		Remove:     true,
	})
	if err != nil {
		return fmt.Errorf("building Docker image %q: %w", tag, err)
	}

	buildErr := drainDockerBuildStream(result.Body, output)
	closeErr := result.Body.Close()
	if buildErr != nil {
		return fmt.Errorf("building Docker image %q: %w", tag, buildErr)
	}
	if closeErr != nil {
		return fmt.Errorf("closing Docker build response for %q: %w", tag, closeErr)
	}
	return nil
}
