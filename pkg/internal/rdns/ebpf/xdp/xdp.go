package xdp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/v2/pkg/internal/rdns/ebpf/rdnscfg"
	"github.com/grafana/beyla/v2/pkg/internal/rdns/store"
)

func log() *slog.Logger {
	return slog.With("component", "xdp.PacketResolver")
}

func PacketResolverProvider(ctx context.Context, cfg *rdnscfg.Config) pipe.StartProvider[store.DNSEntry] {
	return func() (pipe.StartFunc[store.DNSEntry], error) {
		log := log()
		if !slices.Contains(cfg.Resolvers, rdnscfg.EBPFProbeResolverXDP) {
			log.Debug("packet resolver is not enabled, ignoring this stage")
			return pipe.IgnoreStart[store.DNSEntry](), nil
		}

		// todo: instantiate here the eBPF tracer and return any possible error

		tracer, err := newTracer()

		if err != nil {
			return nil, fmt.Errorf("instantiating XDP tracer: %w", err)
		}

		return func(out chan<- store.DNSEntry) {
			tracerLoop(ctx, out, tracer)
		}, nil
	}
}

func tracerLoop(ctx context.Context, out chan<- store.DNSEntry, tracer *tracer) {
	defer tracer.Close()

	log := log()

	log.Debug("listening to packet resolver")

	record := ringbuf.Record{}

	for {
		select {
		case <-ctx.Done():
			log.Debug("context cancelled, exiting..")
			return
		default:
		}

		// the idea here is to avoid copying 'record' when passing it to a
		// channel - this allows its allocated memory to be reused by
		// subsequent ReadInto() calls, allowing the record data to be parsed
		// in place by parseDNSMessage()
		tracer.ringbuf.SetDeadline(time.Now().Add(time.Second))
		err := tracer.ringbuf.ReadInto(&record)

		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Debug("ringbuf closed, exiting..")
				return
			} else if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}

			log.Error("reading from ringbuf", err)
			continue
		}

		entry := handleDNSMessage(&record)

		if entry != nil {
			log.Debug("received DNS entry", "host", entry.HostName, "ips", entry.IPs)
			out <- *entry
		}
	}
}

func handleDNSMessage(rd *ringbuf.Record) *store.DNSEntry {
	dnsMessage := parseDNSMessage(rd.RawSample)

	if dnsMessage == nil || len(dnsMessage.questions) == 0 {
		return nil
	}

	entry := store.DNSEntry{
		HostName: dnsMessage.questions[0].qName,
		IPs: make([]string, 0, len(dnsMessage.answers)),
	}

	for _, answer := range dnsMessage.answers {
		if answer.typ != Type_A {
			continue
		}

		ipStr := net.IP(answer.data).String()
		entry.IPs = append(entry.IPs, ipStr)
	}

	if len(entry.IPs) == 0 {
		return nil
	}

	return &entry
}
