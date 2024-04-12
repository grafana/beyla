package pipe

import "reflect"

type NodesMap interface {
	Connect()
}

type StartFieldPtr[IMPL NodesMap, OUT any] func(IMPL) *Start[OUT]

type MiddleFieldPtr[IMPL NodesMap, IN, OUT any] func(IMPL) *Middle[IN, OUT]

type FinalFieldPtr[IMPL NodesMap, IN any] func(IMPL) *Final[IN]

type StartProvider[OUT any] func() (StartFunc[OUT], error)

type MiddleProvider[IN, OUT any] func() (MiddleFunc[IN, OUT], error)

type FinalProvider[IN any] func() (FinalFunc[IN], error)

func AddStartProvider[IMPL NodesMap, OUT any](p *Builder[IMPL], field StartFieldPtr[IMPL, OUT], provider StartProvider[OUT]) {
	p.startProviders = append(p.startProviders, reflectProvider{
		asNode:      reflect.ValueOf(asStart[OUT]),
		fieldGetter: reflect.ValueOf(field),
		fn:          reflect.ValueOf(provider),
	})
}

func AddMiddleProvider[IMPL NodesMap, IN, OUT any](p *Builder[IMPL], field MiddleFieldPtr[IMPL, IN, OUT], provider MiddleProvider[IN, OUT]) {
	var i IN
	var o OUT
	// middle providers where IN & OUT are the same type can be bypassed if they return
	// a middle function
	var bypassableNode *reflect.Value
	if reflect.TypeOf(i) == reflect.TypeOf(o) {
		rv := reflect.ValueOf(&bypass[IN]{})
		bypassableNode = &rv
	}
	p.midProviders = append(p.midProviders, reflectProvider{
		middleBypasser: bypassableNode,
		asNode:         reflect.ValueOf(asMiddle[IN, OUT]),
		fieldGetter:    reflect.ValueOf(field),
		fn:             reflect.ValueOf(provider),
	})
}

func AddFinalProvider[IMPL NodesMap, IN any](p *Builder[IMPL], field FinalFieldPtr[IMPL, IN], provider FinalProvider[IN]) {
	p.finalProviders = append(p.finalProviders, reflectProvider{
		asNode:      reflect.ValueOf(asFinal[IN]),
		fieldGetter: reflect.ValueOf(field),
		fn:          reflect.ValueOf(provider),
	})

}

func AddStart[IMPL NodesMap, OUT any](p *Builder[IMPL], field StartFieldPtr[IMPL, OUT], fn StartFunc[OUT]) {
	startNode := asStart(fn)
	p.startNodes = append(p.startNodes, startNode)
	*(field(p.nodesMap)) = startNode
}

func AddMiddle[IMPL NodesMap, IN, OUT any](p *Builder[IMPL], field MiddleFieldPtr[IMPL, IN, OUT], fn MiddleFunc[IN, OUT], opts ...Option) {
	*(field(p.nodesMap)) = asMiddle(fn, p.joinOpts(opts...)...)
}

func AddFinal[IMPL NodesMap, IN any](p *Builder[IMPL], field FinalFieldPtr[IMPL, IN], fn FinalFunc[IN], opts ...Option) {
	termNode := asFinal(fn, p.joinOpts(opts...)...)
	p.finalNodes = append(p.finalNodes, termNode)
	*(field(p.nodesMap)) = termNode
}
