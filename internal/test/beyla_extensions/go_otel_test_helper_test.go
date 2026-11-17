//go:build ignore

// buildDockerImageWithContext helper for go_otel integration tests.
// This file is copied to internal/testgenerated/integration/ by generate-obi-tests.sh

package integration

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/moby/moby/client"
)

// buildBeylaDockerImageCLI builds the generated OBI test's Beyla image using
// the Docker CLI. Unlike the Moby SDK, the CLI supplies the BuildKit session
// needed to resolve the image's registry metadata.
func buildBeylaDockerImageCLI(ctx context.Context, output io.Writer, tag, dockerfile string) error {
	buildContext, err := createBuildContext(pathRoot)
	if err != nil {
		return err
	}
	defer buildContext.Close()

	cmd := exec.CommandContext(ctx, "docker", "build", "--quiet", "-t", tag, "-f", dockerfile, "-")
	cmd.Env = dockerBuildKitEnvironment(os.Environ())
	cmd.Stdin = buildContext
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("building Docker image %q: %w", tag, err)
	}
	return nil
}

func dockerBuildKitEnvironment(env []string) []string {
	for i, entry := range env {
		if strings.HasPrefix(entry, "DOCKER_BUILDKIT=") {
			env[i] = "DOCKER_BUILDKIT=1"
			return env
		}
	}
	return append(env, "DOCKER_BUILDKIT=1")
}

// buildDockerImageWithContext builds a Docker image using contextDir as the
// Docker build context root, rather than pathRoot (the Beyla repo root).
// Use this for images whose Dockerfile COPY instructions are relative to a
// directory other than the Beyla repo root — e.g. .obi-src for go_otel.
func buildDockerImageWithContext(ctx context.Context, output io.Writer, tag, contextDir, dockerfile string, buildArgs ...map[string]*string) error {
	buildContext, err := createBuildContext(contextDir)
	if err != nil {
		return err
	}
	defer func() {
		_ = buildContext.Close()
	}()

	var args map[string]*string
	if len(buildArgs) > 0 {
		args = buildArgs[0]
	}
	result, err := dockerPool.Client().ImageBuild(ctx, buildContext, client.ImageBuildOptions{
		Tags:       []string{tag},
		Dockerfile: dockerfile,
		BuildArgs:  args,
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
