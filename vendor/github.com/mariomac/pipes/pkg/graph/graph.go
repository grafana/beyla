package graph

type startNode interface {
	Start()
}

type terminalNode interface {
	Done() <-chan struct{}
}

// Graph is set of Start Nodes that generate information that is forwarded to
// Middle or Terminal nodes, which process that information. It must be created
// from the Builder type.
type Graph struct {
	start []startNode
	terms []terminalNode
}

// Run all the stages of the graph and wait until all the nodes stopped processing.
func (g *Graph) Run() {
	// start all stages
	for _, s := range g.start {
		s.Start()
	}
	// wait for all stages to finish
	for _, t := range g.terms {
		<-t.Done()
	}
}
