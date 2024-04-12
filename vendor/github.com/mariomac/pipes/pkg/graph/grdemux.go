package graph

import (
	"reflect"

	"github.com/mariomac/pipes/pkg/graph/stage"
	"github.com/mariomac/pipes/pkg/node"
)

// RegisterStartDemux registers a stage.StartDemuxProvider into the graph builder. When the Build
// method is invoked later, any configuration field associated with the StartProvider will
// result in the instantiation of a node.StartDemux with the provider's returned provider.
// The passed configuration type must either implement the stage.Instancer interface or the
// configuration struct containing it must define a `nodeId` tag with an identifier for that stage.
// Deprecated. Please use the low-level API of this library as this will be removed in future versions.
func RegisterStartDemux[CFG any](nb *Builder, b stage.StartDemuxProvider[CFG]) {
	nb.startProviders[typeOf[CFG]()] = reflectedNode{
		demuxed:   true,
		instancer: reflect.ValueOf(node.AsStartDemux),
		provider:  reflect.ValueOf(b),
	}
}

// RegisterMiddleDemux registers a stage.MiddleDemuxProvider into the graph builder. When the Build
// method is invoked later, any configuration field associated with the MiddleProvider will
// result in the instantiation of a node.MiddleDemux with the provider's returned provider.
// The passed configuration type must either implement the stage.Instancer interface or the
// configuration struct containing it must define a `nodeId` tag with an identifier for that stage.
// Deprecated. Please use the low-level API of this library as this will be removed in future versions.
func RegisterMiddleDemux[CFG, I any](nb *Builder, b stage.MiddleDemuxProvider[CFG, I]) {
	nb.middleProviders[typeOf[CFG]()] = reflectedNode{
		demuxed:   true,
		instancer: reflect.ValueOf(node.AsMiddleDemux[I]),
		provider:  reflect.ValueOf(b),
		// even if we don't know if the node will receive information from a Demux
		// we need to store the function reference just in case
		inputDemuxAdd: reflect.ValueOf(node.DemuxAdd[I]),
	}
}
