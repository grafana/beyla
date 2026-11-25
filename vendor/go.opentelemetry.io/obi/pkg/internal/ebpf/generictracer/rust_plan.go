// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"errors"
	"fmt"
	"io"
)

type rustProbeAlternative map[rustProbeKind][]uint64

type rustProbeGroup struct {
	name         string
	feature      string
	alternatives []rustProbeAlternative
}

func planRustProbes(symbols rustProbeSymbols) []rustProbeGroup {
	var groups []rustProbeGroup
	add := func(name, feature string, addresses map[rustProbeKind][]uint64, alternatives ...[]rustProbeKind) {
		group := rustProbeGroup{name: name, feature: feature}

		for _, kinds := range alternatives {
			alternative := rustProbeAlternative{}

			for _, kind := range kinds {
				if len(addresses[kind]) == 0 {
					alternative = nil
					break
				}
				alternative[kind] = addresses[kind]
			}

			if len(alternative) > 0 {
				group.alternatives = append(group.alternatives, alternative)
			}
		}

		if len(group.alternatives) > 0 {
			groups = append(groups, group)
		}
	}

	addresses := map[rustProbeKind][]uint64{}
	for kind, offsets := range symbols.addresses {
		addresses[rustProbeKind(kind)] = offsets
	}

	add("Tokio poll", "task-poll", addresses, []rustProbeKind{rustTaskPoll}, []rustProbeKind{rustTaskHarnessPoll})
	add("Tokio deallocation", "task-dealloc", addresses, []rustProbeKind{rustTaskDealloc}, []rustProbeKind{rustTaskHarnessDealloc})
	add("Tokio task binding", "task-create", addresses, []rustProbeKind{rustTaskBind})
	add("Tokio allocation", "task-create", addresses, []rustProbeKind{rustTaskNew}, []rustProbeKind{rustTaskRawNew})
	add("Tokio initial task publication", "task-create", addresses, []rustProbeKind{rustTaskPublish})
	var scheduling []rustProbeKind
	for _, kind := range []rustProbeKind{rustTaskSchedule, rustTaskScheduleLocal} {
		if len(addresses[kind]) > 0 {
			scheduling = append(scheduling, kind)
		}
	}
	if len(scheduling) > 0 {
		add("Tokio spawn scheduling", "task-create", addresses,
			append([]rustProbeKind{rustTaskSpawn}, scheduling...),
			append([]rustProbeKind{rustTaskSpawnPublic}, scheduling...))
	}
	return groups
}

func attachRustGroups(groups []rustProbeGroup, attach func(rustProbeAlternative) ([]io.Closer, error)) ([]io.Closer, map[string]bool, error) {
	var links []io.Closer
	features := map[string]bool{}
	var failures []error

	for _, group := range groups {
		var lastError error

		for _, alternative := range group.alternatives {
			attached, err := attach(alternative)
			if err != nil {
				for _, closer := range attached {
					_ = closer.Close()
				}
				lastError = err
				continue
			}

			links = append(links, attached...)
			features[group.feature] = true
			lastError = nil
			break
		}

		if lastError != nil {
			failures = append(failures, fmt.Errorf("%s: %w", group.name, lastError))
		}
	}

	return links, features, errors.Join(failures...)
}
