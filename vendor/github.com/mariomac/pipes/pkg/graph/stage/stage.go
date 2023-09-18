package stage

import (
	"github.com/mariomac/pipes/pkg/node"
)

// Instance can be embedded into any stage configuration to be instantiable
// (convenience implementation for the required Instancer interface)
type Instance string

func (f Instance) ID() string {
	return string(f)
}

// Instancer is the interface required by any stage configuration type that is
// instantiated from the builder.ApplyConfig method.
type Instancer interface {
	ID() string
}

// Enabler is an optional interface that tells whether a node is enabled. If the node
// config implements it and Enabled() is false, the node won't be added to the graph.
// This is useful for non-nillable configurations that need to be disabled if e.g.
// a property is missing.
// IMPORTANT: The method needs to be implemented by using a value as receiver.
type Enabler interface {
	Enabled() bool
}

var _ Instancer = (*Instance)(nil)
var _ Instancer = Instance("")

// StartProvider is a function that, given a configuration argument of a unique type,
// returns a function fulfilling the node.StartFunc type signature. Returned function
// will run inside a Graph Start Node
// If it returns an error, the graph building process will be interrupted.
// The configuration type must either implement the stage.Instancer interface or the
// configuration struct containing it must define a `nodeId` tag with an identifier for that stage.
type StartProvider[CFG, O any] func(CFG) (node.StartFunc[O], error)

// StartMultiProvider is similar to StarProvider, but it is able to associate a variadic
// number of functions that will behave as a single node.
type StartMultiProvider[CFG, O any] func(CFG) ([]node.StartFunc[O], error)

// MiddleProvider is a function that, given a configuration argument of a unique type,
// returns a function fulfilling the node.MiddleFunc type signature. Returned functions
// will run inside a Graph Middle Node.
// If it returns an error, the graph building process will be interrupted.
// The configuration type must either implement the stage.Instancer interface or the
// configuration struct containing it must define a `nodeId` tag with an identifier for that stage.
type MiddleProvider[CFG, I, O any] func(CFG) (node.MiddleFunc[I, O], error)

// TerminalProvider is a function that, given a configuration argument of a unique type,
// returns a function fulfilling the node.TerminalFunc type signature. Returned functions
// will run inside a Graph Terminal Node.
// If it returns an error, the graph building process will be interrupted.
// The configuration type must either implement the stage.Instancer interface or the
// configuration struct containing it must define a `nodeId` tag with an identifier for that stage.
type TerminalProvider[CFG, I any] func(CFG) (node.TerminalFunc[I], error)
