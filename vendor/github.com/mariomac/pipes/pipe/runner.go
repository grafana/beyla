package pipe

// Runner stores all the configured nodes of a pipeline once their nodes
// are instantiated (as specified by AddStart, AddStartProvider,
// AddMiddle, AddMiddleProvider, AddFinal, AddFinalProvider) and connected
// according to the Connect function of the NodesMap that is provided to
// the Builder.
type Runner struct {
	// startNodes and finalNodes are stored by the uintptr of the destination field
	// in the NodesMap implementation.
	// this way we make sure that we can assign a node to a field twice and only
	// tha last change will prevail, without leaving lost startnodes around there
	startNodes map[uintptr]startable
	finalNodes map[uintptr]doneable
}

// Start the pipeline processing in a background.
func (b *Runner) Start() {
	for _, s := range b.startNodes {
		s.Start()
	}
}

// Done returns a channel that is closed when all the nodes of the
// pipeline have stopped processing data. This is, the functions running
// the node logic have returned.
func (b *Runner) Done() <-chan struct{} {
	done := make(chan struct{})
	go func() {
		for _, s := range b.finalNodes {
			<-s.Done()
		}
		close(done)
	}()
	return done
}
