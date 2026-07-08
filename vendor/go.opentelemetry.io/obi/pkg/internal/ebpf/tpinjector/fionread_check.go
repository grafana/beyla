// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

// Detects kernels where sockhash insertion breaks FIONREAD (commit
// 929e30f93125). cookies non-nil: register the probe socket so an attached
// fixup applies and the corrected behavior is measured
func sockhashFIONREADProbe(cookies *ebpf.Map) (bool, error) {
	sockHash, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "obi_fionread_p",
		Type:       ebpf.SockHash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 2,
	})
	if err != nil {
		return false, fmt.Errorf("creating probe sockhash: %w", err)
	}
	defer sockHash.Close()

	lsn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false, fmt.Errorf("listening on loopback: %w", err)
	}
	defer lsn.Close()

	client, err := net.Dial("tcp", lsn.Addr().String())
	if err != nil {
		return false, fmt.Errorf("connecting to probe listener: %w", err)
	}
	defer client.Close()

	server, err := lsn.Accept()
	if err != nil {
		return false, fmt.Errorf("accepting probe connection: %w", err)
	}
	defer server.Close()

	raw, err := client.(*net.TCPConn).SyscallConn()
	if err != nil {
		return false, fmt.Errorf("getting raw conn: %w", err)
	}
	var fd int
	if err := raw.Control(func(f uintptr) { fd = int(f) }); err != nil {
		return false, fmt.Errorf("getting socket fd: %w", err)
	}

	key := uint64(1)
	if err := sockHash.Update(&key, uint32(fd), ebpf.UpdateAny); err != nil {
		return false, fmt.Errorf("inserting socket into probe sockhash: %w", err)
	}

	if cookies != nil {
		cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
		if err != nil {
			return false, fmt.Errorf("getting socket cookie: %w", err)
		}
		if err := cookies.Update(&cookie, uint8(1), ebpf.UpdateAny); err != nil {
			return false, fmt.Errorf("registering probe cookie: %w", err)
		}
		defer cookies.Delete(&cookie) //nolint:errcheck
	}

	const payload = 4096
	if _, err := server.Write(make([]byte, payload)); err != nil {
		return false, fmt.Errorf("writing probe payload: %w", err)
	}

	// FIONREAD itself is under test, so readiness must come from MSG_PEEK
	buf := make([]byte, payload)
	deadline := time.Now().Add(2 * time.Second)
	for {
		n, _, err := unix.Recvfrom(fd, buf, unix.MSG_PEEK|unix.MSG_DONTWAIT)
		if err == nil && n == payload {
			break
		}
		if time.Now().After(deadline) {
			return false, errors.New("probe payload never became readable")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// TIOCINQ == FIONREAD on Linux; x/sys/unix lacks a FIONREAD alias
	avail, err := unix.IoctlGetInt(fd, unix.TIOCINQ)
	if err != nil {
		return false, fmt.Errorf("ioctl(FIONREAD): %w", err)
	}

	return avail != payload, nil
}

func (p *Tracer) kernelBreaksFIONREAD() bool {
	p.fionreadOnce.Do(func() {
		broken, err := sockhashFIONREADProbe(nil)
		if err != nil {
			p.log.Warn("FIONREAD sockhash probe failed", "error", err)
			return
		}
		p.fionreadBroken = broken
		if broken {
			p.log.Warn("kernel misreports ioctl(FIONREAD) for sockets in a sockhash " +
				"(kernel commit 929e30f93125, present in 6.6.128+, 6.12.75+, 6.18.14+ and 6.19+); " +
				"enabling BPF compensation for tracked sockets")
		}
	})
	return p.fionreadBroken
}

// test-load on a throwaway copy so LoadSpecs can skip the bundle on kernels
// that reject bpf_probe_write_user (lockdown)
func loadableFIONREADFixup() (*ebpf.CollectionSpec, error) {
	spec, err := LoadBpfFionreadFixup()
	if err != nil {
		return nil, err
	}
	test := spec.Copy()
	for _, m := range test.Maps {
		if m.Pinning == ebpfconvenience.PinInternal {
			m.Pinning = ebpf.PinNone
		}
	}
	coll, err := ebpf.NewCollection(test)
	if err != nil {
		return nil, err
	}
	coll.Close()
	return spec, nil
}

// end-to-end check that the attached fixup actually corrects FIONREAD
func (p *Tracer) verifyFIONREADFix() {
	stillBroken, err := sockhashFIONREADProbe(p.bpfObjects.TrackedSockCookies)
	if err != nil {
		p.log.Warn("cannot verify FIONREAD compensation", "error", err)
		return
	}
	if stillBroken {
		p.log.Error("FIONREAD compensation is ineffective (attach failed or blocked?); " +
			"applications sizing reads via FIONREAD (nginx, Java, .NET) may stall or " +
			"truncate transfers; set context_propagation: disabled " +
			"(OTEL_EBPF_BPF_CONTEXT_PROPAGATION=disabled) to avoid impact")
		return
	}
	p.log.Info("FIONREAD compensation verified")
}
