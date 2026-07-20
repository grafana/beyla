// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package docker // import "go.opentelemetry.io/obi/pkg/docker"

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
)

const (
	composeServiceLabelKey = "com.docker.compose.service"
	// abbreviationLength defines the length for the short ID form
	abbreviationLength = 12
)

func cmlog() *slog.Logger {
	return slog.With("component", "docker.ContainerStore")
}

var osInfoForPID = container.InfoForPID

// Full length ID as provided by the docker API
type ContainerID string

type ContainerMeta struct {
	// TODO: add other fields https://opentelemetry.io/docs/specs/semconv/resource/container/
	ID             string // short form ID limited to abbreviationLength
	FullID         ContainerID
	Name           string
	ComposeService string
}

// containerEntry groups container metadata with the PIDs known to belong to it.
// This allows a single map lookup to both retrieve metadata and support PID-based invalidation.
type containerEntry struct {
	meta ContainerMeta
	pids []app.PID
}

// dockerClient defines the Docker API methods needed by ContainerStore.
type dockerClient interface {
	ContainerInspect(ctx context.Context, container string, options client.ContainerInspectOptions) (client.ContainerInspectResult, error)
	Events(ctx context.Context, options client.EventsListOptions) client.EventsResult
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
	initMutex      sync.Mutex
	docker         dockerClient
	log            *slog.Logger
	watcherStarted sync.Once
	watcherRunning atomic.Bool

	cacheMu       sync.RWMutex
	byPID         map[app.PID]ContainerMeta
	byContainerID map[ContainerID]containerEntry // metadata + PIDs keyed by full container ID

	// lastEventAt is the Unix timestamp (seconds) of the last processed Docker event.
	// It is seeded to the start time of watchContainerEvents and updated on each event,
	// so that eventsLoop can set EventsListOptions.Since on reconnects to avoid missing
	// die/destroy events that arrived during the 1-second backoff gap.
	lastEventAt atomic.Int64
}

func NewStore() *ContainerStore {
	return &ContainerStore{
		log:           cmlog(),
		byPID:         make(map[app.PID]ContainerMeta),
		byContainerID: make(map[ContainerID]containerEntry),
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
	if result, err := docker.Info(ctx, client.InfoOptions{}); err != nil {
		s.log.Debug("failed to get docker info", "error", err)
		return
	} else {
		s.log.Info("Docker info",
			"driver", result.Info.Driver,
			"version", result.Info.ServerVersion,
			"cgroupDriver", result.Info.CgroupDriver,
			"cgroupVersion", result.Info.CgroupVersion)
		s.docker = docker
	}
}

// ContainerInfo returns the ContainerMeta that is associated to the provided PID.
// It also returns true if the ContainerMeta was found for the provided PID. False otherwise
func (s *ContainerStore) ContainerInfo(ctx context.Context, pid app.PID) (ContainerMeta, bool) {
	s.cacheMu.RLock()
	if ci, ok := s.byPID[pid]; ok {
		s.cacheMu.RUnlock()
		return ci, true
	}
	s.cacheMu.RUnlock()

	osCntInfo, err := osInfoForPID(pid)
	if err != nil {
		s.log.Debug("failed to get OS container info for pid", "pid", pid, "error", err)
		return ContainerMeta{}, false
	}

	// Reuse metadata if another PID from the same container is already cached.
	// We acquire the write lock directly to avoid a TOCTOU race: if the container
	// is invalidated between the read check and the write, we must not cache stale metadata.
	fullContainerID := ContainerID(osCntInfo.ContainerID)
	s.cacheMu.Lock()
	if entry, ok := s.byContainerID[fullContainerID]; ok {
		// Re-validate that the PID still belongs to this container while holding the lock.
		currentInfo, err := osInfoForPID(pid)
		if err != nil || ContainerID(currentInfo.ContainerID) != fullContainerID {
			s.cacheMu.Unlock()
			return ContainerMeta{}, false
		}
		meta := entry.meta
		seen := false
		for _, cachedPID := range entry.pids {
			if cachedPID == pid {
				seen = true
				break
			}
		}
		if !seen {
			entry.pids = append(entry.pids, pid)
			s.byContainerID[fullContainerID] = entry
		}
		s.byPID[pid] = meta
		s.cacheMu.Unlock()
		return meta, true
	}
	s.cacheMu.Unlock()

	inspectResult, err := s.docker.ContainerInspect(ctx, osCntInfo.ContainerID, client.ContainerInspectOptions{})
	if err != nil {
		s.log.Debug("failed to inspect docker container",
			"pid", pid,
			"id", osCntInfo.ContainerID,
			"error", err)
		return ContainerMeta{}, false
	}

	inspectInfo := inspectResult.Container
	containerID := inspectInfo.ID
	if len(containerID) > abbreviationLength {
		containerID = containerID[:abbreviationLength]
	}

	composeSvcName := ""
	if inspectInfo.Config != nil && len(inspectInfo.Config.Labels) > 0 {
		composeSvcName = inspectInfo.Config.Labels[composeServiceLabelKey]
	}

	meta := ContainerMeta{
		// some containers start with '/'. Removing it
		Name:           strings.Trim(inspectInfo.Name, "/"),
		ID:             containerID,
		FullID:         ContainerID(inspectInfo.ID),
		ComposeService: composeSvcName,
	}

	s.cacheMu.Lock()
	// Re-validate that the PID still belongs to the inspected container: the process
	// may have exited while ContainerInspect was in flight, causing InvalidatePID to
	// be a no-op (byPID entry didn't exist yet), and we would cache stale metadata.
	currentInfo, err := osInfoForPID(pid)
	if err != nil || ContainerID(currentInfo.ContainerID) != meta.FullID {
		s.cacheMu.Unlock()
		return ContainerMeta{}, false
	}
	if entry, ok := s.byContainerID[meta.FullID]; ok {
		meta = entry.meta
		seen := false
		for _, cachedPID := range entry.pids {
			if cachedPID == pid {
				seen = true
				break
			}
		}
		if !seen {
			entry.pids = append(entry.pids, pid)
		}
		s.byPID[pid] = meta
		s.byContainerID[meta.FullID] = entry
		s.cacheMu.Unlock()
		return meta, true
	}
	s.byPID[pid] = meta
	s.byContainerID[meta.FullID] = containerEntry{meta: meta, pids: []app.PID{pid}}
	s.cacheMu.Unlock()

	return meta, true
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

// Start begins the event watcher goroutine to invalidate and remove
// metadata of destroyed containers.
func (s *ContainerStore) Start(ctx context.Context) {
	if s == nil {
		return
	}
	s.watcherStarted.Do(func() {
		s.initMutex.Lock()
		s.initialize(ctx)
		s.initMutex.Unlock()
		s.lastEventAt.Store(time.Now().Unix())
		s.watcherRunning.Store(true)
		go s.watchContainerEvents(ctx)
	})
}

// WatcherRunning reports whether the die/destroy event watcher goroutine
// has been launched via Start.
func (s *ContainerStore) WatcherRunning() bool {
	if s == nil {
		return false
	}
	return s.watcherRunning.Load()
}

func (s *ContainerStore) watchContainerEvents(ctx context.Context) {
	for {
		s.initMutex.Lock()
		s.initialize(ctx)
		docker := s.docker
		s.initMutex.Unlock()

		if docker == nil {
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				return
			}
			continue
		}

		fltrs := make(client.Filters).
			Add("type", string(events.ContainerEventType)).
			Add("event", string(events.ActionDie), string(events.ActionDestroy))

		// Subtract one second from the checkpoint so reconnects overlap slightly.
		// Invalidation is idempotent, so processing an event twice is safe.
		since := s.lastEventAt.Load() - 1
		if err := s.eventsLoop(ctx, fltrs, since); err != nil && !errors.Is(err, context.Canceled) {
			s.log.Debug("docker event stream error", "error", err)
		}

		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return
		}
	}
}

func (s *ContainerStore) eventsLoop(ctx context.Context, fltrs client.Filters, since int64) error {
	result := s.docker.Events(ctx, client.EventsListOptions{
		Filters: fltrs,
		Since:   strconv.FormatInt(since, 10),
	})
	for {
		select {
		case msg, ok := <-result.Messages:
			if !ok {
				return nil
			}
			s.lastEventAt.Store(time.Now().Unix())
			if msg.Actor.ID != "" {
				s.invalidateContainer(msg.Actor.ID)
			}
		case err, ok := <-result.Err:
			if !ok || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case <-ctx.Done():
			return context.Canceled
		}
	}
}

func (s *ContainerStore) InvalidatePID(pid app.PID) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	meta, ok := s.byPID[pid]
	if !ok {
		return
	}
	delete(s.byPID, pid)

	entry := s.byContainerID[meta.FullID]
	newPIDs := entry.pids[:0]
	for _, cachedPID := range entry.pids {
		if cachedPID != pid {
			newPIDs = append(newPIDs, cachedPID)
		}
	}

	if len(newPIDs) == 0 {
		delete(s.byContainerID, meta.FullID)
		return
	}
	s.byContainerID[meta.FullID] = containerEntry{meta: entry.meta, pids: newPIDs}
}

func (s *ContainerStore) invalidateContainer(containerID string) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	for _, pid := range s.byContainerID[ContainerID(containerID)].pids {
		delete(s.byPID, pid)
	}
	delete(s.byContainerID, ContainerID(containerID))
}
