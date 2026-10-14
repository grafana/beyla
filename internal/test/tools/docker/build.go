// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package docker // import "go.opentelemetry.io/obi/internal/test/integration/components/docker"

import (
	"io"
	"log/slog"
	"os/exec"
)

// ImageBuild information for testing docker images: its name/tag and where the dockerfile is located.
// If the dockerfile is null, it will try pulling the image.
type ImageBuild struct {
	Tag        string
	Dockerfile string
}

// Build a set of Dockerfile images
func Build(logger io.WriteCloser, rootPath string, imgs ...ImageBuild) error {
	log := slog.With("component", "docker.Build", "rootPath", rootPath)
	for _, img := range imgs {
		ilog := log.With("dockerfile", img.Dockerfile, "tag", img.Tag)
		if img.Dockerfile != "" {
			if err := buildDockerfile(logger, rootPath, ilog, img); err != nil {
				return err
			}
		} else {
			if err := pullDockerfile(logger, ilog, img); err != nil {
				return err
			}
		}
	}
	return nil
}

func pullDockerfile(logger io.WriteCloser, ilog *slog.Logger, img ImageBuild) error {
	ilog.Info("pulling Dockerfile")

	cmd := exec.Command("docker", "pull", "--quiet", img.Tag)
	if logger != nil {
		cmd.Stdout = logger
		cmd.Stderr = logger
	}
	if err := cmd.Run(); err != nil {
		ilog.Error("pulling dockerfile. Check logs for details", "error", err)
		return err
	}
	return nil
}

func buildDockerfile(logger io.WriteCloser, rootPath string, ilog *slog.Logger, img ImageBuild) error {
	ilog.Info("building Dockerfile")

	cmd := exec.Command("docker", "build", "--quiet", "-t", img.Tag, "-f", img.Dockerfile, rootPath)
	if logger != nil {
		cmd.Stdout = logger
		cmd.Stderr = logger
	}
	if err := cmd.Run(); err != nil {
		ilog.Error("building dockerfile. Check build logs for details", "error", err)
		return err
	}
	// OpenTelemetry images are very limited in disk. Remove dangling images after building each image
	ilog.Info("removing docker builder cache")
	cmd = exec.Command("docker", "builder", "prune", "-af")
	if logger != nil {
		cmd.Stdout = logger
		cmd.Stderr = logger
	}
	if err := cmd.Run(); err != nil {
		ilog.Warn("Can't remove docker builder cache. Tests will continue anyway", "error", err)
	}
	return nil
}
