// Package node provides functionalities to create nodes and interconnect them.
// A Node is a function container that can be connected via channels to other nodes.
// A node can send data to multiple nodes, and receive data from multiple nodes.
//
//nolint:unused
package pipe

import (
	"errors"

	"github.com/mariomac/pipes/pipe/internal/connect"
)

// StartFunc is a function that receives a writable channel as unique argument, and sends
// value to that channel during an indefinite amount of time.
type StartFunc[OUT any] func(out chan<- OUT)

// MiddleFunc is a function that receives a readable channel as first argument,
// and a writable channel as second argument.
// It must process the inputs from the input channel until it's closed.
type MiddleFunc[IN, OUT any] func(in <-chan IN, out chan<- OUT)

// FinalFunc is a function that receives a readable channel as unique argument.
// It must process the inputs from the input channel until it's closed.
type FinalFunc[IN any] func(in <-chan IN)

// Start is any node that can send data to another node: node.start, node.doubler and node.bypass
type Start[OUT any] interface {
	// SendTo connect a sender with a group of receivers
	SendTo(r ...Final[OUT])
}

// Final is any node that can receive data from another node: node.bypass, node.doubler and node.terminal
type Final[IN any] interface {
	isStarted() bool
	start()
	// joiners will usually return only one joiner instance but in
	// the case of a BypassNode, which might return the joiners of
	// all their destination nodes
	joiners() []*connect.Joiner[IN]
}

// Middle is any node that can both send and receive data: node.bypass or node.doubler.
type Middle[IN, OUT any] interface {
	Final[IN]
	Start[OUT]
}

// start nodes are the starting points of a pipeline. This is, all the nodes that bring information
// from outside the pipeline: e.g. because they generate them or because they acquire them from an
// external source like a Web Service.
// A pipe must have at least one active start node.
// An start node must have at least one output node.
type start[OUT any] struct {
	receiverGroup[OUT]
	fun StartFunc[OUT]
}

// middle is any intermediate node that receives data from another node, processes/filters it,
// and forwards the data to another node.
// An middle node must have at least one output node.
type middle[IN, OUT any] struct {
	outs    []Final[OUT]
	inputs  connect.Joiner[IN]
	started bool
	fun     MiddleFunc[IN, OUT]
}

func (m *middle[IN, OUT]) joiners() []*connect.Joiner[IN] {
	return []*connect.Joiner[IN]{&m.inputs}
}

func (m *middle[IN, OUT]) isStarted() bool {
	return m.started
}

func (m *middle[IN, OUT]) SendTo(outputs ...Final[OUT]) {
	m.outs = append(m.outs, outputs...)
}

// terminal is any node that receives data from another node and does not forward it to another node,
// but can process it and send the results to outside the pipeline (e.g. memory, storage, web...)
type terminal[IN any] struct {
	inputs  connect.Joiner[IN]
	started bool
	fun     FinalFunc[IN]
	done    chan struct{}
}

func (t *terminal[IN]) joiners() []*connect.Joiner[IN] {
	if t == nil {
		return nil
	}
	return []*connect.Joiner[IN]{&t.inputs}
}

func (t *terminal[IN]) isStarted() bool {
	if t == nil {
		return false
	}
	return t.started
}

// Done returns a channel that is closed when the terminal node has ended its processing. This
// is, when all its inputs have been also closed. Waiting for all the terminal nodes to finish
// allows blocking the execution until all the data in the pipeline has been processed and all the
// previous stages have ended
func (t *terminal[IN]) Done() <-chan struct{} {
	if t == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return t.done
}

// asStart wraps a group of StartFunc with the same signature into a start node.
// TODO: let just 1 start function as argument
func asStart[OUT any](fun StartFunc[OUT]) *start[OUT] {
	if fun == nil {
		return nil
	}
	return &start[OUT]{
		fun:           fun,
		receiverGroup: receiverGroup[OUT]{},
	}
}

// asMiddle wraps an MiddleFunc into an middle node.
func asMiddle[IN, OUT any](fun MiddleFunc[IN, OUT], opts ...Option) *middle[IN, OUT] {
	options := getOptions(opts...)
	return &middle[IN, OUT]{
		inputs: connect.NewJoiner[IN](options.channelBufferLen),
		fun:    fun,
	}
}

// asFinal wraps a FinalFunc into a terminal node.
func asFinal[IN any](fun FinalFunc[IN], opts ...Option) *terminal[IN] {
	if fun == nil {
		return nil
	}
	options := getOptions(opts...)
	return &terminal[IN]{
		inputs: connect.NewJoiner[IN](options.channelBufferLen),
		fun:    fun,
		done:   make(chan struct{}),
	}
}

// Start the function wrapped in the start node. This method should be invoked
// for all the start nodes of the same pipeline, so the pipeline can properly start and finish.
func (i *start[OUT]) Start() {
	// a nil start node can be started without no effect on the pipeline.
	// this allows setting optional nillable start nodes and let start all of them
	// as a group in a more convenient way
	if i == nil {
		return
	}
	forker, err := i.receiverGroup.StartReceivers()
	if err != nil {
		panic("start: " + err.Error())
	}

	go func() {
		i.fun(forker.AcquireSender())
		forker.ReleaseSender()
	}()
}

func (m *middle[IN, OUT]) start() {
	if len(m.outs) == 0 {
		panic("doubler node should have outputs")
	}
	m.started = true
	joiners := make([]*connect.Joiner[OUT], 0, len(m.outs))
	for _, out := range m.outs {
		joiners = append(joiners, out.joiners()...)
		if !out.isStarted() {
			out.start()
		}
	}
	forker := connect.Fork(joiners...)
	go func() {
		m.fun(m.inputs.Receiver(), forker.AcquireSender())
		forker.ReleaseSender()
	}()
}

func (t *terminal[IN]) start() {
	if t == nil {
		return
	}
	t.started = true
	go func() {
		t.fun(t.inputs.Receiver())
		close(t.done)
	}()
}

func getOptions(opts ...Option) creationOptions {
	options := defaultOptions
	for _, opt := range opts {
		opt(&options)
	}
	return options
}

// receiverGroup connects a sender node with a collection
// of Final nodes through a common connect.Forker instance.
type receiverGroup[OUT any] struct {
	Outs []Final[OUT]
}

// SendTo connects a group of receivers to the current receiverGroup
func (s *start[OUT]) SendTo(outputs ...Final[OUT]) {
	// a nil start node can be operated without no effect on the pipeline.
	// this allows connecting optional nillable start nodes and let start all of them
	// as a group in a more convenient way
	if s != nil {
		s.receiverGroup.SendTo(outputs...)
	}
}

func (s *receiverGroup[OUT]) SendTo(outputs ...Final[OUT]) {
	s.Outs = append(s.Outs, outputs...)
}

// StartReceivers start the receivers and return a connection
// forker to them
func (i *receiverGroup[OUT]) StartReceivers() (*connect.Forker[OUT], error) {
	if len(i.Outs) == 0 {
		return nil, errors.New("node should have outputs")
	}
	joiners := make([]*connect.Joiner[OUT], 0, len(i.Outs))
	for _, out := range i.Outs {
		joiners = append(joiners, out.joiners()...)
		if !out.isStarted() {
			out.start()
		}
	}
	forker := connect.Fork(joiners...)
	return &forker, nil
}
