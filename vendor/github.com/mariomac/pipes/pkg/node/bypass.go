package node

import (
	"reflect"

	"github.com/mariomac/pipes/pkg/node/internal/connect"
)

// Bypass node just makes sure, at graph construction time, that the inputs of this node
// are bypassed to the destination nodes.
// At a logical level, you can see a Bypass node as a Middle[T, T] node that just forwards
// its input to the output channel.
// At an implementation level, Bypass[T] is much more efficient because it just makes sure
// that its input channel is connected to its destination nodes, without adding any extra
// goroutine nor channel operation.
// Bypass is useful for implementing constructors that might return an optional Middle[T, T] node
// (according to e.g. the user configuration) or just a Bypass[T] node to transparently
// forward data to the destination nodes.
// Deprecated package. Use github.com/mariomac/pipes/pipe package
type Bypass[INOUT any] struct {
	outs []Receiver[INOUT]
}

func (b *Bypass[INOUT]) SendTo(r ...Receiver[INOUT]) {
	b.outs = append(b.outs, r...)
}

func (b *Bypass[INOUT]) InType() reflect.Type {
	return b.OutType()
}

func (b *Bypass[INOUT]) OutType() reflect.Type {
	var v INOUT
	return reflect.TypeOf(v)
}

// nolint:unused
// golangci-lint bug: it's actually used through its interface
func (b *Bypass[INOUT]) isStarted() bool {
	// returns true if all the forwarded nodes are started
	started := true
	for _, o := range b.outs {
		started = started && o.isStarted()
	}
	return started
}

// nolint:unused
// golangci-lint bug: it's actually used through its interface
func (b *Bypass[INOUT]) start() {
	if len(b.outs) == 0 {
		panic("Bypass node should have outputs")
	}
	for _, o := range b.outs {
		if !o.isStarted() {
			o.start()
		}
	}
}

// nolint:unused
// golangci-lint bug: it's actually used through its interface
func (b *Bypass[INOUT]) joiners() []*connect.Joiner[INOUT] {
	joiners := make([]*connect.Joiner[INOUT], 0, len(b.outs))
	for _, o := range b.outs {
		joiners = append(joiners, o.joiners()...)
	}
	return joiners
}
