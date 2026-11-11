// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package liveprober // import "go.opentelemetry.io/obi/pkg/liveprober"

import (
	"errors"
	"io"
	"reflect"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
)

const (
	patchStatusAttached = "attached"
	patchStatusExpired  = "expired"
)

// PatchTarget is implemented by targets whose runtime can host live patches (Java).
type PatchTarget interface {
	AttachLivePatch(pid app.PID, patch *config.PatchSpec, expiresAt time.Time, cookie uint64) (io.Closer, error)
}

type patchKey struct {
	pid    int
	target string
}

type patchAttachment struct {
	cookie uint64
	spec   config.PatchSpec
	result ProbeResult
	link   io.Closer
}

// patchExpiries anchors each patch's expiry to the rule, not to an attachment, so re-attaching
// after a JVM restart reuses the original deadline. Resubmitting an unchanged patch keeps its
// deadline; a changed or new patch gets a fresh one. Expiry is in memory only: an OBI restart
// starts the TTL again.
func patchExpiries(prior ruleState, rule config.DynamicInstrumentationRule) map[string]time.Time {
	expiries := make(map[string]time.Time, len(rule.Patches))
	for _, spec := range rule.Patches {
		target := spec.Target()
		expiries[target] = time.Now().Add(spec.TTL)
		for _, old := range prior.definition.Patches {
			if old.Target() == target && reflect.DeepEqual(old, spec) {
				if kept, ok := prior.patchExpiry[target]; ok {
					expiries[target] = kept
				}
			}
		}
	}
	return expiries
}

// reconcilePatchesLocked attaches the patches a rule asks for on one process and records them in
// desired. The rule's absolute expiry is reused for every attach, and a patch past its expiry is
// reported as expired rather than applied again.
func (m *Manager) reconcilePatchesLocked(pid int, rule ruleState, desired map[patchKey]config.PatchSpec) []ProbeResult {
	var results []ProbeResult
	bound, ready := m.targets[pid]
	for _, spec := range rule.definition.Patches {
		result := m.resultLocked(pid, spec.Target(), "")
		key := patchKey{pid: pid, target: spec.Target()}
		prior, conflict := desired[key]
		switch {
		case !ready:
			result.Status = "pending"
		case m.targetGoneLocked(pid, bound):
			result.Status, result.Error = "error", ErrTargetGone.Error()
		case conflict && !reflect.DeepEqual(prior, spec):
			result.Status, result.Error = "error", "patch already requested with a different definition"
		default:
			desired[key] = spec
			result = m.ensurePatchLocked(key, bound, spec, rule.patchExpiry[spec.Target()], result)
		}
		results = append(results, result)
	}
	return results
}

func (m *Manager) targetGoneLocked(pid int, bound target) bool {
	identity, err := m.identity(pid)
	return err != nil || identity != bound.identity
}

func (m *Manager) ensurePatchLocked(key patchKey, bound target, spec config.PatchSpec, expiresAt time.Time, result ProbeResult) ProbeResult {
	current := m.patches[key]
	expired := !time.Now().Before(expiresAt)
	if current != nil && reflect.DeepEqual(current.spec, spec) {
		result.Status = patchStatusAttached
		if expired {
			result.Status = patchStatusExpired
		}
		current.result = result
		return result
	}
	if expired {
		result.Status = patchStatusExpired
		return result
	}
	patcher, ok := bound.tracer.(PatchTarget)
	if !ok {
		result.Status, result.Error = "error", "target runtime does not support patches"
		return result
	}
	if current == nil && len(m.patches) >= m.maxProbes {
		result.Status, result.Error = "error", "dynamic probe limit reached"
		return result
	}
	m.nextCookie++
	link, err := patcher.AttachLivePatch(app.PID(key.pid), &spec, expiresAt, m.nextCookie)
	if err == nil && current != nil {
		if err = current.link.Close(); err != nil {
			_ = link.Close()
		}
	}
	if err != nil {
		result.Status, result.Error = "error", err.Error()
		return result
	}
	result.Status = patchStatusAttached
	m.patches[key] = &patchAttachment{cookie: m.nextCookie, spec: spec, result: result, link: link}
	return result
}

func (m *Manager) removeStalePatchesLocked(desired map[patchKey]config.PatchSpec) error {
	var joined error
	for key := range m.patches {
		if _, keep := desired[key]; !keep {
			joined = errors.Join(joined, m.removePatchLocked(key))
		}
	}
	return joined
}

func (m *Manager) removePatchLocked(key patchKey) error {
	if err := m.patches[key].link.Close(); err != nil {
		return err
	}
	delete(m.patches, key)
	return nil
}
