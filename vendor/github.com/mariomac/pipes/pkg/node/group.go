package node

// Starter abstracts any Start node
type Starter interface {
	Start()
}

// Doner abstracts any Terminal node
type Doner interface {
	Done() <-chan struct{}
}

// StartAll is a helper function to start in background all the Start nodes of a given pipeline
func StartAll(startNodes ...Starter) {
	for _, s := range startNodes {
		s.Start()
	}
}

// DoneAll is a helper function returns a channel that is closed after all the passed Terminal nodes are done
func DoneAll(termNodes ...Doner) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		for _, s := range termNodes {
			<-s.Done()
		}
		close(done)
	}()
	return done
}
