package rdns

import (
	"context"
	"fmt"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/v2/pkg/internal/rdns/ebpf/addrinfo"
	"github.com/grafana/beyla/v2/pkg/internal/rdns/ebpf/rdnscfg"
	"github.com/grafana/beyla/v2/pkg/internal/rdns/ebpf/xdp"
	"github.com/grafana/beyla/v2/pkg/internal/rdns/store"
)



type Pipeline struct {
	packetResolver      pipe.Start[store.DNSEntry]
	getAddrInfoResolver pipe.Start[store.DNSEntry]
	store               pipe.Final[store.DNSEntry]
}

func (p *Pipeline) Packet() *pipe.Start[store.DNSEntry]      { return &p.packetResolver }
func (p *Pipeline) GetAddrInfo() *pipe.Start[store.DNSEntry] { return &p.getAddrInfoResolver }
func (p *Pipeline) Store() *pipe.Final[store.DNSEntry]       { return &p.store }

func (p *Pipeline) Connect() {
	p.packetResolver.SendTo(p.store)
	p.getAddrInfoResolver.SendTo(p.store)
}

type storage interface {
	PipelineStage(in <-chan store.DNSEntry)
	GetHostnames(ip string) []string
}

func Run(ctx context.Context, cfg *rdnscfg.Config, storage storage) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	builder := pipe.NewBuilder(&Pipeline{})
	pipe.AddStartProvider(builder, (*Pipeline).Packet, xdp.PacketResolverProvider(ctx, cfg))
	pipe.AddStartProvider(builder, (*Pipeline).GetAddrInfo, addrinfo.AddrInfoProvider(ctx, cfg))
	pipe.AddFinal(builder, (*Pipeline).Store, storage.PipelineStage)

	run, err := builder.Build()
	if err != nil {
		return fmt.Errorf("building pipeline: %w", err)
	}

	run.Start()
	<-run.Done()
	return nil
}
