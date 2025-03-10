package addrinfo

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/v2/pkg/internal/rdns/ebpf/rdnscfg"
	"github.com/grafana/beyla/v2/pkg/internal/rdns/store"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 -type dns_entry_t Bpf ../../../../../bpf/rdns_addrinfo.c -- -I../../../../../bpf/headers

func log() *slog.Logger {
	return slog.With(
		slog.String("component", "addrinfo.Tracer"),
	)
}

func AddrInfoProvider(ctx context.Context, cfg *rdnscfg.Config) pipe.StartProvider[store.DNSEntry] {
	return func() (pipe.StartFunc[store.DNSEntry], error) {
		log := log()
		if !slices.Contains(cfg.Resolvers, rdnscfg.EBPFProbeGetAddrInfo) {
			log.Debug("getaddrinfo resolver is not enabled, ignoring this stage")
			return pipe.IgnoreStart[store.DNSEntry](), nil
		}

		// Instantiating the eBPF tracer and allocating resources
		tracer, err := newTracer(log)
		if err != nil {
			return nil, fmt.Errorf("instantiating eBPF tracer: %w", err)
		}

		return func(out chan<- store.DNSEntry) {
			defer tracer.Close()
			log.Debug("listening to getaddrinfo resolver")
			for {
				// check for context cancellation
				go tracer.readNext()
				select {
				case <-ctx.Done():
					log.Debug("context cancelled, exiting..")
					return
				case err := <-tracer.readErrors:
					if errors.Is(err, ringbuf.ErrClosed) {
						log.Debug("ringbuf closed. Exiting..")
						return
					}
					log.Error("reading from ringbuf", err)
					continue
				case entry := <-tracer.readEntries:
					end := bytes.IndexByte(entry.Name[:], 0)
					if end == -1 {
						end = len(entry.Name)
					}
					de := store.DNSEntry{
						HostName: string(entry.Name[:end]),
						// TODO: getaddrinfo can return multiple IPs. Amend the BPF program for it
						// TODO: support IPv6
						IPs: []string{net.IP(entry.Ip[:4]).String()},
					}
					log.Debug("received DNS entry", "host", de.HostName, "ip", de.IPs[0])
					out <- de
				}
			}
		}, nil
	}
}

type tracer struct {
	log        *slog.Logger
	bpfObjects BpfObjects
	uprobe     link.Link
	uretprobe  link.Link
	ringbuf    *ringbuf.Reader

	readEntries chan BpfDnsEntryT
	readErrors  chan error
}

func newTracer(log *slog.Logger) (*tracer, error) {
	t := tracer{
		log:         log,
		readErrors:  make(chan error),
		readEntries: make(chan BpfDnsEntryT),
	}
	if err := t.register(); err != nil {
		return nil, fmt.Errorf("registering eBPF tracer: %w", err)
	}
	log.Debug("creating ringbuf reader")
	var err error
	t.ringbuf, err = ringbuf.NewReader(t.bpfObjects.Resolved)
	if err != nil {
		_ = t.Close()
		return nil, fmt.Errorf("creating ringbuf reader: %w", err)
	}
	return &t, nil
}

func (t *tracer) register() error {
	log := log()
	// Allow the current process to lock memory for eBPF resources.
	log.Debug("Registering eBPF tracer")
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Warn("removing mem lock", "error", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	log.Debug("loading BPF objects")
	if err := LoadBpfObjects(&t.bpfObjects, nil); err != nil {
		verr := &ebpf.VerifierError{}
		if !errors.As(err, &verr) {
			return fmt.Errorf("loading BPF objects: %w", err)
		}
		return fmt.Errorf("loading BPF objects: %w, %s", err, strings.Join(verr.Log, "\n"))
	}

	log.Debug("registering uprobes")

	libc, err := t.locateLibC()
	if err != nil {
		return err
	}

	exec, err := link.OpenExecutable(libc)
	if err != nil {
		return fmt.Errorf("opening executable: %w", err)
	}
	t.uprobe, err = exec.Uprobe("getaddrinfo", t.bpfObjects.UprobeGetaddrinfo, nil)
	if err != nil {
		return fmt.Errorf("registering uprobe: %w", err)
	}
	t.uretprobe, err = exec.Uretprobe("getaddrinfo", t.bpfObjects.UretprobeGetaddrinfo, nil)

	return nil
}

func (t *tracer) readNext() {
	record, err := t.ringbuf.Read()
	if err != nil {
		t.readErrors <- err
	}
	input := bytes.NewBuffer(record.RawSample)
	dnsEntry := BpfDnsEntryT{}
	if err := binary.Read(input, binary.LittleEndian, &dnsEntry); err != nil {
		t.log.Error("reading ringbuf event", "error", err)
	}
	t.readEntries <- dnsEntry
}

func (t *tracer) Close() error {
	t.log.Debug("closing uprobe")
	if t.uprobe != nil {
		if err := t.uprobe.Close(); err != nil {
			t.log.Error("closing uprobe", "error", err)
		}
	}
	t.log.Debug("closing BPF objects")
	if err := t.bpfObjects.Close(); err != nil {
		t.log.Error("closing BPF objects", "error", err)
	}
	return nil
}

func (t *tracer) locateLibC() (string, error) {
	libc, err := ldCacheFind("libc.so.6")

	if err != nil {
		t.log.Debug("ldCacheFind", "error", err)
	}

	if libc == "" {
		t.log.Debug("could not find libc in ldcache, using fallback method")
	}

	commonLocations := []string{
		"/lib/libc.so.6",
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/lib/i386-linux-gnu/libc.so.6",
		"/lib/aarch64-linux-gnu/libc.so.6",
		"/usr/lib/libc.so.6",
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/lib/aarch64-linux-gnu/libc.so.6",
		"/lib64/libc.so.6",
	}

	for _, loc := range commonLocations {
		if _, err := os.Stat(loc); err == nil {
			return loc, nil
		}
	}

	return "", fmt.Errorf("could not find libc.so.6")
}
