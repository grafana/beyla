package pipe

import (
	"fmt"
	"reflect"
)

type startable interface {
	Start()
}

type doneable interface {
	Done() <-chan struct{}
}

// Builder provides tools and functions to create a pipeline and add nodes and node providers to it.
type Builder[IMPL NodesMap] struct {
	nodesMap IMPL
	opts     []Option

	// startNodes and finalNodes are stored by the uintptr of the destination field
	// in the NodesMap implementation.
	// this way we make sure that we can assign a node to a field twice and only
	// tha last change will prevail, without leaving lost startnodes around there
	startNodes map[uintptr]nodeOrProvider[startable]
	// in middle nodes, we only care about providers and we don't really care about the node implementation
	middleNodes map[uintptr]nodeOrProvider[struct{}]
	finalNodes  map[uintptr]nodeOrProvider[doneable]
}

type nodeOrProvider[N any] struct {
	node     N
	provider *reflectProvider
}

// NewBuilder creates a pipeline builder whose nodes and connections are defined by the
// passed NodesMap implementation.
// It accepts a set of default options that would apply to all the nodes and connections
// in the pipeline.
func NewBuilder[IMPL NodesMap](nodesMap IMPL, defaultOpts ...Option) *Builder[IMPL] {
	return &Builder[IMPL]{
		nodesMap:    nodesMap,
		opts:        defaultOpts,
		startNodes:  map[uintptr]nodeOrProvider[startable]{},
		middleNodes: map[uintptr]nodeOrProvider[struct{}]{},
		finalNodes:  map[uintptr]nodeOrProvider[doneable]{},
	}
}

func (b *Builder[IMPL]) joinOpts(opts ...Option) []Option {
	var opt []Option
	opt = append(opt, b.opts...)
	opt = append(opt, opts...)
	return opt
}

// reflected providers hides some "reflection magic" to allow connecting nodes from diverse
// input and output types. Despite reflection API is not type safe, the typesafe public Go API
// ensures that, for example, you can't connect two nodes from different out->in types.
type reflectProvider struct {
	// start and final nodes accept nillable functions. Middle nodes require creating a bypasser
	acceptNilFunc  bool
	middleBypasser *reflect.Value
	asNode         reflect.Value
	fieldGetter    reflect.Value
	fn             reflect.Value
}

func (rp *reflectProvider) call(nodesMap interface{}) (reflect.Value, uintptr, error) {
	// nodeFn, err := Provider()
	res := rp.fn.Call(nil)
	nodeFn, err := res[0], res[1]
	if !err.IsNil() {
		return reflect.Value{}, 0, fmt.Errorf("error invoking provider: %w", err.Interface().(error))
	}
	// fieldPtr = fieldGetter(nodesMap)
	fieldPtr := rp.fieldGetter.Call([]reflect.Value{reflect.ValueOf(nodesMap)})[0]

	// a middle node getting a nil function is a bypasser
	var node reflect.Value
	if nodeFn.IsNil() && !rp.acceptNilFunc {
		if rp.middleBypasser != nil {
			// node = bypass[T]{}
			node = *rp.middleBypasser
		} else {
			return reflect.Value{}, 0, fmt.Errorf("middle provider returned a nil function. Expecting %s", nodeFn.Type().String())
		}
	} else {
		// node = AsNode(nodeFn)
		node = rp.asNode.Call([]reflect.Value{nodeFn})[0]
	}
	// *fieldPtr = AsNode(nodeFn)
	fieldPtr.Elem().Set(node)
	return node, fieldPtr.Pointer(), nil
}

// Build a pipe Runner ready to Start processing data until all the nodes are Done.
func (b *Builder[IMPL]) Build() (*Runner, error) {
	runner := &Runner{
		startNodes: map[uintptr]startable{},
		finalNodes: map[uintptr]doneable{},
	}
	for dstPtr, sn := range b.startNodes {
		if sp := sn.provider; sp == nil {
			// node explicitly set via AddStart, AddMiddle, AddFinal
			runner.startNodes[dstPtr] = sn.node
		} else {
			// node provided from AddStartProvider argument func
			sp := sn.provider
			if node, dstFieldPtr, err := sp.call(b.nodesMap); err != nil {
				return nil, fmt.Errorf("invoking Start node provider: %w", err)
			} else {
				runner.startNodes[dstFieldPtr] = node.Interface().(startable)
			}
		}
	}
	for _, mn := range b.middleNodes {
		// we only care about nodes added by AddMiddleProviders, as nodes
		// from AddMiddle are already created and assigned to its field
		if mp := mn.provider; mp != nil {
			if _, _, err := mp.call(b.nodesMap); err != nil {
				return nil, fmt.Errorf("invoking Middle node provider: %w", err)
			}
		}
	}
	for dstPtr, fn := range b.finalNodes {
		if fp := fn.provider; fp == nil {
			// node explicitly set via AddFinal
			runner.finalNodes[dstPtr] = fn.node
		} else {
			// node provided from AddMiddleProvider argument func
			if node, dstFieldPtr, err := fp.call(b.nodesMap); err != nil {
				return nil, fmt.Errorf("invoking Final node provider: %w", err)
			} else {
				runner.finalNodes[dstFieldPtr] = node.Interface().(doneable)
			}
		}
	}
	b.nodesMap.Connect()
	return runner, nil
}
