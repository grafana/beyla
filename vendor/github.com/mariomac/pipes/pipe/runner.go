package pipe

type Runner struct {
	startNodes []startable
	finalNodes []doneable
}

func (b *Runner) Start() {
	for _, s := range b.startNodes {
		s.Start()
	}
}

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
