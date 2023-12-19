package testutil

import "github.com/mariomac/pipes/pkg/node"

type ChannelInput[T any] struct {
	In chan T
}

func ChannelInputProvider[T any](in ChannelInput[T]) node.StartFunc[T] {
	if in.In == nil {
		in.In = make(chan T)
	}
	return func(out chan<- T) {
		for i := range in.In {
			out <- i
		}
	}
}

type ChannelOutput[T any] struct {
	Out chan T
}

func ChannelOutputProvider[T any](out ChannelOutput[T]) node.TerminalFunc[T] {
	if out.Out == nil {
		out.Out = make(chan T)
	}
	return func(in <-chan T) {
		for i := range in {
			out.Out <- i
		}
	}
}
