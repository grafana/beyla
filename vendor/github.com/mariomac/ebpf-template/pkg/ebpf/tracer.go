package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/exp/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type state_info bpf ../../bpf/probes.c -- -I../../bpf/headers

var log = slog.With(
	slog.String("component", "ebpf.Tracer"),
)

type tracer struct {
	bpfObjects bpfObjects
	tracepoint link.Link
}

func (t *tracer) register() error {
	// Allow the current process to lock memory for eBPF resources.
	log.Debug("Registering eBPF tracer")
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Warn("removing mem lock", "error", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	log.Debug("loading BPF objects")
	if err := loadBpfObjects(&t.bpfObjects, nil); err != nil {
		verr := &ebpf.VerifierError{}
		if !errors.As(err, &verr) {
			return fmt.Errorf("loading BPF objects: %w", err)
		}
		return fmt.Errorf("loading BPF objects: %w, %s", err, strings.Join(verr.Log, "\n"))
	}

	log.Debug("registering tracepoint")
	kp, err := link.Tracepoint("sock", "inet_sock_set_state", t.bpfObjects.InetSockSetState, nil)
	//kp, err := link.Kretprobe("inet_csk_accept", objs.TcpV4Rcv, nil)
	if err != nil {
		return fmt.Errorf("registering tracepoint: %w", err)
	}
	t.tracepoint = kp
	return nil
}

func (t *tracer) Close() error {
	var errs []string
	if t.tracepoint != nil {
		if err := t.tracepoint.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if err := t.bpfObjects.Close(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("closing BPF resources: '%s'", strings.Join(errs, "', '"))
	}
	return nil
}

type SockStateInfo bpfStateInfo

func Trace() (func(out chan<- SockStateInfo), error) {
	t := tracer{}
	if err := t.register(); err != nil {
		return nil, fmt.Errorf("registering eBPF tracer: %w", err)
	}
	slog.Debug("creating ringbuf reader")
	rd, err := ringbuf.NewReader(t.bpfObjects.Connections)
	if err != nil {
		_ = t.Close()
		return nil, fmt.Errorf("creating ringbuf reader: %w", err)
	}
	return func(out chan<- SockStateInfo) {
		defer t.Close()
		var conn SockStateInfo
		// TODO: set proper context-based cancellation
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Debug("Received signal, exiting..")
					return
				}
				log.Error("reading from ringbuf", err)
				continue
			}

			// Parse the ringbuf event entry into a bpfEvent structure.
			// TODO: detect endianness
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &conn); err != nil {
				log.Error("parsing ringbuf event", err)
				continue
			}
			out <- conn
		}
	}, nil
}
