package connect

import (
	"sync/atomic"
)

// Joiner provides shared access to the input channel of a node of the type IN
type Joiner[IN any] struct {
	totalSenders int32
	bufLen       int
	channel      chan IN
}

// NewJoiner creates a joiner for a given channel type and buffer length
func NewJoiner[IN any](bufferLength int) Joiner[IN] {
	return Joiner[IN]{
		bufLen:  bufferLength,
		channel: make(chan IN, bufferLength),
	}
}

// Receiver gets access to the channel as a receiver
func (j *Joiner[IN]) Receiver() chan IN {
	return j.channel
}

// AcquireSender gets acces to the channel as a sender. The acquirer must finally invoke
// ReleaseSender to make sure that the channel is closed when all the senders released it.
func (j *Joiner[IN]) AcquireSender() chan IN {
	atomic.AddInt32(&j.totalSenders, 1)
	return j.channel
}

// ReleaseSender will close the channel when all the invokers of the AcquireSender have invoked
// this function
func (j *Joiner[IN]) ReleaseSender() {
	// if no senders, we close the main channel
	if atomic.AddInt32(&j.totalSenders, -1) == 0 {
		close(j.channel)
	}
}

// Releaser is a function that will allow releasing a forked channel.
type Releaser func()

// Forker manages the access to a Node's output (send) channel. When a node sends to only
// one node, this will work as a single channel. When a node sends to N nodes,
// it will spawn N channels that are cloned from the original channel in a goroutine.
type Forker[OUT any] struct {
	sendCh         chan OUT
	releaseChannel Releaser
}

// Fork provides connection to a group of output Nodes, accessible through their respective
// Joiner instances.
func Fork[T any](joiners ...*Joiner[T]) Forker[T] {
	if len(joiners) == 0 {
		panic("can't fork 0 joiners")
	}
	// if there is only one joiner, we directly send the data to the channel, without intermediation
	if len(joiners) == 1 {
		return Forker[T]{
			sendCh:         joiners[0].AcquireSender(),
			releaseChannel: joiners[0].ReleaseSender,
		}
	}
	// channel used as input from the source Node
	sendCh := make(chan T, joiners[0].bufLen)

	// channels that clone the contents of the sendCh
	forwarders := make([]chan T, len(joiners))
	for i := 0; i < len(joiners); i++ {
		forwarders[i] = joiners[i].AcquireSender()
	}
	go func() {
		for in := range sendCh {
			for i := 0; i < len(joiners); i++ {
				forwarders[i] <- in
			}
		}
		for i := 0; i < len(joiners); i++ {
			joiners[i].ReleaseSender()
		}
	}()
	return Forker[T]{
		sendCh:         sendCh,
		releaseChannel: func() { close(sendCh) },
	}
}

// Sender acquires the channel that will receive the data from the source node
func (f *Forker[OUT]) Sender() chan OUT {
	return f.sendCh
}

// Close the input channel and, in cascade, all the forked channels
func (f *Forker[OUT]) Close() {
	f.releaseChannel()
}
