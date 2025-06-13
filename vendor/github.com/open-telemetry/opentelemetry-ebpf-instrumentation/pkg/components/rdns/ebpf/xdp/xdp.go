package xdp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/ringbuf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/rdns/store"
)

func log() *slog.Logger {
	return slog.With("component", "xdp.DNSPacketInspector")
}

// storage backend for DNS IP-->Hostnames relation
type storage interface {
	Store(*store.DNSEntry)
	GetHostnames(ip string) ([]string, error)
}

// StartDNSPacketInspector in a backgound goroutine
func StartDNSPacketInspector(ctx context.Context, storage storage) error {
	tracer, err := newTracer()
	if err != nil {
		return fmt.Errorf("instantiating XDP tracer: %w", err)
	}

	go tracerLoop(ctx, storage, tracer)

	return nil
}

func tracerLoop(ctx context.Context, storage storage, tracer *tracer) {
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
			} else if !errors.Is(err, os.ErrDeadlineExceeded) {
				log.Error("reading from ringbuf", "error", err)
			}
			continue
		}

		entry := handleDNSMessage(&record)

		if entry != nil {
			log.Debug("received DNS entry", "host", entry.HostName, "ips", entry.IPs)
			storage.Store(entry)
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
		IPs:      make([]string, 0, len(dnsMessage.answers)),
	}

	for _, answer := range dnsMessage.answers {
		if answer.typ != TypeA {
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
