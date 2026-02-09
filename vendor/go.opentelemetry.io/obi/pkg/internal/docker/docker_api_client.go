// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package docker // import "go.opentelemetry.io/obi/pkg/internal/docker"

import (
	"context"
	"log/slog"
	"maps"
	"strings"
	"sync"

	"github.com/docker/docker/client"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
)

const composeServiceLabelKey = "com.docker.compose.service"

func cmlog() *slog.Logger {
	return slog.With("component", "docker.ContainerStore")
}

var osInfoForPID = container.InfoForPID

type ContainerMeta struct {
	// TODO: add other fields https://opentelemetry.io/docs/specs/semconv/resource/container/
	ID             string
	Name           string
	ComposeService string
}

// ContainerStore caches access to the Docker container API.
// The behavior can be overridden via environment variables:
//   - DOCKER_HOST to set the URL to the docker server.
//   - DOCKER_API_VERSION to set the version of the
//     API to use, leave empty for negotiation.
//   - DOCKER_CERT_PATH to specify the directory from
//     which to load the TLS certificates ("ca.pem", "cert.pem", "key.pem').
//   - DOCKER_TLS_VERIFY to enable or disable TLS verification
//     (off by default).
type ContainerStore struct {
	initMutex sync.Mutex
	docker    client.ContainerAPIClient
	log       *slog.Logger
}

func NewStore() *ContainerStore {
	return &ContainerStore{
		log: cmlog(),
	}
}

func (s *ContainerStore) IsEnabled(ctx context.Context) bool {
	if s == nil {
		return false
	}
	s.initMutex.Lock()
	defer s.initMutex.Unlock()
	s.initialize(ctx)
	return s.docker != nil
}

func (s *ContainerStore) initialize(ctx context.Context) {
	if s.docker != nil {
		return
	}

	docker, err := client.NewClientWithOpts(
		client.WithAPIVersionNegotiation(),
		client.FromEnv,
	)
	if err != nil {
		s.log.Debug("trying to instantiate docker client", "error", err)
		return
	}
	if info, err := docker.Info(ctx); err != nil {
		s.log.Debug("failed to get docker info", "error", err)
		return
	} else {
		s.log.Info("Docker info",
			"driver", info.Driver,
			"version", info.ServerVersion,
			"cgroupDriver", info.CgroupDriver,
			"cgroupVersion", info.CgroupVersion)
		s.docker = docker
	}
}

// ContainerInfo returns the ContainerMeta that is associated to the provided PID.
// It also returns true if the ContainerMeta was found for the provided PID. False otherwise
func (s *ContainerStore) ContainerInfo(ctx context.Context, pid app.PID) (ContainerMeta, bool) {
	osCntInfo, err := osInfoForPID(pid)
	if err != nil {
		s.log.Debug("failed to get OS container info for pid", "pid", pid, "error", err)
		return ContainerMeta{}, false
	}
	inspectInfo, err := s.docker.ContainerInspect(ctx, osCntInfo.ContainerID)
	if err != nil {
		s.log.Debug("failed to inspect docker container",
			"pid", pid,
			"id", osCntInfo.ContainerID,
			"error", err)
		return ContainerMeta{}, false
	}

	const abbreviationLength = 12
	containerID := inspectInfo.ID
	if len(containerID) > abbreviationLength {
		containerID = containerID[:abbreviationLength]
	}

	composeSvcName := ""
	if inspectInfo.Config != nil && len(inspectInfo.Config.Labels) > 0 {
		composeSvcName = inspectInfo.Config.Labels[composeServiceLabelKey]
	}

	return ContainerMeta{
		// some containers start with '/'. Removing it
		Name:           strings.Trim(inspectInfo.Name, "/"),
		ID:             containerID,
		ComposeService: composeSvcName,
	}, true
}

func (ci *ContainerMeta) DecorateService(s *svc.Attrs) {
	s.Metadata = ContainerMetadata(s.Metadata, ci, func(n attr.Name) attr.Name {
		return n
	})

	if s.AutoName() {
		// populate service name from container metadata
		if ci.ComposeService != "" {
			s.UID.Name = ci.ComposeService
		} else {
			s.UID.Name = ci.Name
		}
	}
	// overriding the Instance here will avoid reusing the OTEL resource reporter
	// if the application/process was discovered and reported information
	// before the docker metadata was available
	// Service Instance ID is set according to OTEL collector conventions.
	if s.UID.Namespace == "" {
		if ci.ComposeService == "" {
			s.UID.Instance = ci.Name
		} else {
			s.UID.Instance = ci.ComposeService + "." + ci.Name
		}
	} else {
		s.UID.Instance = s.UID.Namespace + "." + s.UID.Name + "." + ci.Name
	}
}

func ContainerMetadata[T ~string](dst map[T]string, ci *ContainerMeta, stringer func(attr.Name) T) map[T]string {
	// Copy map to avoid concurrent read/write on shared Metadata
	var out map[T]string
	if dst == nil {
		out = map[T]string{}
	} else {
		out = maps.Clone(dst)
	}
	out[stringer(attr.ContainerName)] = ci.Name
	out[stringer(attr.ContainerID)] = ci.ID
	return out
}
