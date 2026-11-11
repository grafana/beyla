// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"errors"
	"io"
	"sync"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
)

type javaSpanRegistration struct {
	tracer *Tracer
	cookie uint64
	once   sync.Once
	err    error
}

func (p *Tracer) RegisterJavaSpan(pid app.PID, span *config.CustomSpanSpec, cookie uint64, id string, generation uint64) (io.Closer, error) {
	if err := p.bpfObjects.ObiDynamicInvocations.Update(cookie, uint64(0), ebpf.UpdateNoExist); err != nil {
		return nil, err
	}
	if err := p.bpfObjects.ObiJavaDynamicProbes.Update(cookie, uint32(pid), ebpf.UpdateNoExist); err != nil {
		_ = p.bpfObjects.ObiDynamicInvocations.Delete(cookie)
		return nil, err
	}
	p.customSpan.RegisterJava(span, cookie, id, generation)
	return &javaSpanRegistration{tracer: p, cookie: cookie}, nil
}

func (r *javaSpanRegistration) Invocations() (uint64, error) {
	var count uint64
	err := r.tracer.bpfObjects.ObiDynamicInvocations.Lookup(r.cookie, &count)
	return count, err
}

func (r *javaSpanRegistration) Close() error {
	r.once.Do(func() {
		r.tracer.customSpan.Remove(r.cookie)
		for _, m := range []*ebpf.Map{r.tracer.bpfObjects.ObiJavaDynamicProbes, r.tracer.bpfObjects.ObiDynamicInvocations} {
			if err := m.Delete(r.cookie); !errors.Is(err, ebpf.ErrKeyNotExist) {
				r.err = errors.Join(r.err, err)
			}
		}
		var key BpfTraceKeyT
		var value BpfJavaDynamicContext
		entries := r.tracer.bpfObjects.JavaDynamicSpans.Iterate()
		for entries.Next(&key, &value) {
			if value.Cookie == r.cookie {
				_ = r.tracer.bpfObjects.JavaDynamicSpans.Delete(&key)
			}
		}
	})
	return r.err
}
