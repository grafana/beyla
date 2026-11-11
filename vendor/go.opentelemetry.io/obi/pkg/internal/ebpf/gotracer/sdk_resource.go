// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gotracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"

import (
	"bytes"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
)

var goSDKResourceOffsetFields = [...]goexec.GoOffset{
	goexec.SDKTracerProviderPos,
	goexec.SDKProviderResourcePos,
	goexec.SDKResourceAttrsPos,
	goexec.SDKAttributeSetDataPos,
}

type sdkServiceUpdater interface {
	UpdateServiceFromSDK(app.PID, uint32, uint64, string, string) (*exec.FileInfo, bool)
}

func (p *Tracer) handleSDKResource(record *ringbuf.Record, updated func(app.PID, svc.Attrs)) error {
	event, err := ebpfcommon.ReinterpretCast[BpfGoSdkResourceEvent](record.RawSample)
	if err != nil {
		return err
	}
	filter, ok := p.pidsFilter.(sdkServiceUpdater)
	if !ok {
		return nil
	}
	name := string(bytes.TrimRight(event.ServiceName[:], "\x00"))
	namespace := string(bytes.TrimRight(event.ServiceNamespace[:], "\x00"))
	info, changed := filter.UpdateServiceFromSDK(app.PID(event.Pid.UserPid), event.Pid.Ns, event.Timestamp, name, namespace)
	if info == nil {
		return nil
	}
	if changed && updated != nil {
		updated(info.Pid(), info.ServiceAttrs())
	}
	if p.bpfObjects.GoSdkResourcesSeen != nil {
		return p.bpfObjects.GoSdkResourcesSeen.Put(event.Key, ^uint64(0))
	}
	return nil
}
