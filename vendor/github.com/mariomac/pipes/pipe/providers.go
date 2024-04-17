package pipe

import (
	"reflect"
)

// NodesMap is any data structure that stores references to the nodes of a pipeline,
// and specifies how to connect them by means of its Connect method.
// Example:
//
//	type MyPipeline struct {
//		Load      pipe.Start[string]
//		Transform pipe.Middle[string, string]
//		Store     pipe.Final[string]
//	}
//	func (m *MyPipeline) Connect() {
//		m.Load.SendTo(m.Transform)
//		m.Transform.SendTo(m.Store)
//	}
//
// The fields are assigned to nodes by the Builder, by means of
// AddStart, AddStartProvider, AddMiddle, AddMiddleProvider, AddFinal and AddFinalProvider
type NodesMap interface {
	// Connect runs the code that connects the nodes of a pipeline. It is invoked
	// by the Builder before returning the pipeline Runner.
	Connect()
}

// StartPtr is a function that, given a NodesMap, returns a pointer to a
// Start node, which is going to be used as store destination
// when this function is passed as argument to AddStartProvider
// or AddStart functions.
type StartPtr[IMPL NodesMap, OUT any] func(IMPL) *Start[OUT]

// MiddlePtr is a function that, given a NodesMap, returns a pointer to a
// Middle node, which is going to be used as store destination
// when this function is passed as argument to AddMiddleProvider
// or AddMiddle functions.
type MiddlePtr[IMPL NodesMap, IN, OUT any] func(IMPL) *Middle[IN, OUT]

// FinalPtr is a function that, given a NodesMap, returns a pointer to a
// Final node, which is going to be used as store destination
// when this function is passed as argument to AddFinalProvider
// or AddFinal functions.
type FinalPtr[IMPL NodesMap, IN any] func(IMPL) *Final[IN]

// StartProvider is a function that returns a StartFunc to be used as
// Start node in a pipeline. It also might return an error if there is a
// problem with the configuration or instantiation of the function.
//
// If both the returned function and the error are nil, the start
// node will be ignored and would be equivalent to not adding it
// to the pipeline.
//
// For readability, don't do:
//
//	return nil, nil
//
// instead, use the equivalent convenience function:
//
//	return IgnoreStart[T](), nil
type StartProvider[OUT any] func() (StartFunc[OUT], error)

// MiddleProvider is a function that returns a MiddleFunc to be used as
// Middle node in a pipeline. It also might return an error if there is a
// problem with the configuration or instantiation of the function.
//
// If the IN and OUT types are different, the returned function can't be
// nil unless an error is returned.
//
// If the IN and OUT type is the same, and both the returned function and
// the error are nil, the middle
// node will be bypassed and would be equivalent to not adding it to the
// pipeline, dyrectly bypassing the connection between its Sender nodes
// to its Receiver nodes.
//
// For readability, don't do:
//
//	return nil, nil
//
// instead, use the equivalent convenience function:
//
//	return Bypass[T](), nil
type MiddleProvider[IN, OUT any] func() (MiddleFunc[IN, OUT], error)

// FinalProvider is a function that returns a FinalFunc to be used as
// Final node in a pipeline. It also might return an error if there is a
// problem with the configuration or instantiation of the function.
//
// If both the returned function and the error are nil, the middle
// node will be ignored and would be equivalent to not adding it
// to the pipeline.
//
// For readability, don't do:
//
//	return nil, nil
//
// instead, use the equivalent convenience function:
//
//	return IgnoreFinal[T](), nil
type FinalProvider[IN any] func() (FinalFunc[IN], error)

// AddStartProvider registers a StartProviderFunc into the pipeline Builder.
// The function returned by the StartProvider will be assigned to the NodesMap
// field whose pointer is returned by the passed StartPtr function.
func AddStartProvider[IMPL NodesMap, OUT any](p *Builder[IMPL], field StartPtr[IMPL, OUT], provider StartProvider[OUT]) {
	dstAddress := reflect.ValueOf(field(p.nodesMap)).Pointer()
	p.startNodes[dstAddress] = nodeOrProvider[startable]{
		provider: &reflectProvider{
			acceptNilFunc: true,
			asNode:        reflect.ValueOf(asStart[OUT]),
			fieldGetter:   reflect.ValueOf(field),
			fn:            reflect.ValueOf(provider),
		}}
}

// AddMiddleProvider registers a MiddleProvider into the pipeline Builder.
// The function returned by the MiddleProvider will be assigned to the NodesMap
// field whose pointer is returned by the passed MiddlePtr function.
func AddMiddleProvider[IMPL NodesMap, IN, OUT any](p *Builder[IMPL], field MiddlePtr[IMPL, IN, OUT], provider MiddleProvider[IN, OUT]) {
	var i IN
	var o OUT
	// middle providers where IN & OUT are the same type can be bypassed if they return
	// a middle function
	var bypassableNode *reflect.Value
	if reflect.TypeOf(i) == reflect.TypeOf(o) {
		rv := reflect.ValueOf(&bypass[IN]{})
		bypassableNode = &rv
	}
	dstAddress := reflect.ValueOf(field(p.nodesMap)).Pointer()
	p.middleNodes[dstAddress] = nodeOrProvider[struct{}]{
		provider: &reflectProvider{
			middleBypasser: bypassableNode,
			asNode:         reflect.ValueOf(asMiddle[IN, OUT]),
			fieldGetter:    reflect.ValueOf(field),
			fn:             reflect.ValueOf(provider),
		}}
}

// AddFinalProvider registers a FinalProvider into the pipeline Builder.
// The function returned by the FinalProvider will be assigned to the NodesMap
// field whose pointer is returned by the passed FinalPtr function.
func AddFinalProvider[IMPL NodesMap, IN any](p *Builder[IMPL], field FinalPtr[IMPL, IN], provider FinalProvider[IN]) {
	dstAddress := reflect.ValueOf(field(p.nodesMap)).Pointer()
	p.finalNodes[dstAddress] = nodeOrProvider[doneable]{
		provider: &reflectProvider{
			acceptNilFunc: true,
			asNode:        reflect.ValueOf(asFinal[IN]),
			fieldGetter:   reflect.ValueOf(field),
			fn:            reflect.ValueOf(provider),
		}}
}

// AddStart creates a Start node given the provided StartFunc. The node will
// be assigned to the field of the NodesMap whose pointer is returned by the
// provided StartPtr function.
func AddStart[IMPL NodesMap, OUT any](p *Builder[IMPL], field StartPtr[IMPL, OUT], fn StartFunc[OUT]) {
	startNode := asStart(fn)
	dstAddress := field(p.nodesMap)
	p.startNodes[reflect.ValueOf(dstAddress).Pointer()] = nodeOrProvider[startable]{node: startNode}
	*(dstAddress) = startNode
}

// AddMiddle creates a Middle node given the provided MiddleFunc. The node will
// be assigned to the field of the NodesMap whose pointer is returned by the
// provided MiddlePtr function.
// The options related to the connection to that Middle node can be overridden. Otherwise
// the global options passed to the pipeline Builder are used.
func AddMiddle[IMPL NodesMap, IN, OUT any](p *Builder[IMPL], field MiddlePtr[IMPL, IN, OUT], fn MiddleFunc[IN, OUT], opts ...Option) {
	dstAddress := field(p.nodesMap)
	p.middleNodes[reflect.ValueOf(dstAddress).Pointer()] = nodeOrProvider[struct{}]{}
	*(dstAddress) = asMiddle(fn, p.joinOpts(opts...)...)
}

// AddFinal creates a Final node given the provided FinalFunc. The node will
// be assigned to the field of the NodesMap whose pointer is returned by the
// provided FinalPtr function.
// The options related to the connection to that Final node can be overridden. Otherwise
// the global options passed to the pipeline Builder are used.
func AddFinal[IMPL NodesMap, IN any](p *Builder[IMPL], field FinalPtr[IMPL, IN], fn FinalFunc[IN], opts ...Option) {
	termNode := asFinal(fn, p.joinOpts(opts...)...)
	dstAddress := field(p.nodesMap)
	p.finalNodes[reflect.ValueOf(dstAddress).Pointer()] = nodeOrProvider[doneable]{node: termNode}
	*(dstAddress) = termNode
}
