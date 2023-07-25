package docker

import (
	"io"
	"os/exec"

	"golang.org/x/exp/slog"
)

// ImageBuild information for testing docker images: its name/tag and where the dockerfile is located
type ImageBuild struct {
	Tag        string
	Dockerfile string
}

// Build a set of Dockerfile images
func Build(logger io.WriteCloser, rootPath string, imgs ...ImageBuild) error {
	log := slog.With("component", "docker.Build", "rootPath", rootPath)
	for _, img := range imgs {
		ilog := log.With("dockerfile", img.Dockerfile, "tag", img.Tag)
		ilog.Info("building Dockerfile")

		cmd := exec.Command("docker", "build", "-t", img.Tag, "-f", img.Dockerfile, rootPath)
		if logger != nil {
			cmd.Stdout = logger
			cmd.Stderr = logger
		}
		if err := cmd.Run(); err != nil {
			ilog.Error("building dockerfile. Check build logs for details", err)
			return err
		}
	}
	return nil
}
