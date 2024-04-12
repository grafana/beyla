package pipe

import (
	"fmt"
	"reflect"
	"slices"
)

type startable interface {
	Start()
}

type doneable interface {
	Done() <-chan struct{}
}

type Builder[IMPL NodesMap] struct {
	nodesMap   IMPL
	opts       []Option
	startNodes []startable
	finalNodes []doneable

	startProviders []reflectProvider
	midProviders   []reflectProvider
	finalProviders []reflectProvider
}

func NewBuilder[IMPL NodesMap](nodesMap IMPL, defaultOpts ...Option) *Builder[IMPL] {
	return &Builder[IMPL]{nodesMap: nodesMap, opts: defaultOpts}
}

func (b *Builder[IMPL]) joinOpts(opts ...Option) []Option {
	var opt []Option
	opt = append(opt, b.opts...)
	opt = append(opt, opts...)
	return opt
}

// reflected providers
type reflectProvider struct {
	middleBypasser *reflect.Value
	asNode         reflect.Value
	fieldGetter    reflect.Value
	fn             reflect.Value
}

func (rp *reflectProvider) call(nodesMap interface{}) (reflect.Value, error) {
	// nodeFn, err := Provider()
	res := rp.fn.Call(nil)
	nodeFn, err := res[0], res[1]
	if !err.IsNil() {
		return reflect.Value{}, fmt.Errorf("error invoking start provider: %w", err.Interface().(error))
	}
	// fieldPtr = fieldGetter(nodesMap)
	fieldPtr := rp.fieldGetter.Call([]reflect.Value{reflect.ValueOf(nodesMap)})[0]

	// a middle node getting a nil function is a bypasser
	var node reflect.Value
	if nodeFn.IsNil() {
		if rp.middleBypasser != nil {
			// node = bypass[T]{}
			node = *rp.middleBypasser
		} else {
			return reflect.Value{}, fmt.Errorf("middle provider returned a nil function. Expecting %s", nodeFn.Type().String())
		}
	} else {
		// node = AsNode(nodeFn)
		node = rp.asNode.Call([]reflect.Value{nodeFn})[0]
	}
	// *fieldPtr = AsNode(nodeFn)
	fieldPtr.Elem().Set(node)
	return node, nil
}

func (b *Builder[IMPL]) Build() (*Runner, error) {
	runner := &Runner{
		startNodes: slices.Clone(b.startNodes),
		finalNodes: slices.Clone(b.finalNodes),
	}
	for _, sp := range b.startProviders {
		if node, err := sp.call(b.nodesMap); err != nil {
			return nil, fmt.Errorf("invoking Start node provider: %w", err)
		} else {
			runner.startNodes = append(runner.startNodes, node.Interface().(startable))
		}
	}
	for _, mp := range b.midProviders {
		if _, err := mp.call(b.nodesMap); err != nil {
			return nil, fmt.Errorf("invoking Middle node provider: %w", err)
		}
	}
	for _, fp := range b.finalProviders {
		if node, err := fp.call(b.nodesMap); err != nil {
			return nil, fmt.Errorf("invoking Final node provider: %w", err)
		} else {
			runner.finalNodes = append(runner.finalNodes, node.Interface().(doneable))
		}
	}
	b.nodesMap.Connect()
	return runner, nil
}
