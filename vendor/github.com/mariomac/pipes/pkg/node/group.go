package node

// Starter abstracts any Start node
// Deprecated package. Use github.com/mariomac/pipes/pipe package
type Starter interface {
	Start()
}

// Doner abstracts any Terminal node
// Deprecated package. Use github.com/mariomac/pipes/pipe package
type Doner interface {
	Done() <-chan struct{}
}

// StartAll is a helper function to start in background all the Start nodes of a given pipeline
// Deprecated package. Use github.com/mariomac/pipes/pipe package
func StartAll(startNodes ...Starter) {
	for _, s := range startNodes {
		s.Start()
	}
}

// DoneAll is a helper function returns a channel that is closed after all the passed Terminal nodes are done
// Deprecated package. Use github.com/mariomac/pipes/pipe package
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
