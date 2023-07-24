package ebpfauto

import "context"

type TracerConfig struct{}

type Process interface{}

func FindProcess(t *TracerConfig) Process {

}

// go-pipes definition
type ProcessorConfig struct{}

type Processor struct {
	Config *ProcessorConfig
}

func (p *Processor) Attach(process Process) {

}

// Start in background
func (p *Processor) Start(ctx context.Context) {

}


func pseudoMain() {
	t := TracerConfig{}
}
