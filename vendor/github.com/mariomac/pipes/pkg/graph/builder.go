package graph

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/mariomac/pipes/pkg/graph/stage"
	"github.com/mariomac/pipes/pkg/node"
)

const (
	nodeIdTag    = "nodeId"
	sendsToTag   = "sendTo"
	fwdToTag     = "forwardTo"
	nodeIdIgnore = "-"
)

type codecKey struct {
	In  reflect.Type
	Out reflect.Type
}

// outTyper is any node with an output channel: node.Start, node.Middle
type outTyper interface {
	OutType() reflect.Type
}

// inTyper is any node with an input channel: node.Middle, node.Terminal, node.MiddleDemux, node.TerminalDemux
type inTyper interface {
	InType() reflect.Type
}

// inOutTyper is any node with an input and an output channel: node.Middle
type inOutTyper interface {
	inTyper
	outTyper
}

// inDemuxedOutTyper type is any node with an input channel and an output Demux: node.MiddleDemux
type inDemuxedOutTyper interface {
	inTyper
	node.Demuxed
}

// destinableInNode stores information about any node that can be connected as output of another node.
// It keeps information about the input node and a reflected reference to DemuxAdd[T]
type destinableInNode struct {
	node          inTyper
	inputDemuxAdd reflect.Value
}

// destinableInOutNode stores information about any node that can be connected as output of another node,
// and also has an output to another node.
// it keeps information about the in/out node and a reflected reference to DemuxAdd[T]
type destinableInOutNode struct {
	node          inOutTyper
	inputDemuxAdd reflect.Value
}

type reflectedDemuxedNode struct {
	node          inTyper
	inputDemuxAdd reflect.Value
	demuxed       node.Demuxed // nillable
}

type reflectedNode struct {
	demuxed bool
	// reflect value of AsStart, AsMiddle, etc...
	instancer reflect.Value
	// reflect value of StartFunc, MiddleFunc, etc...
	provider reflect.Value
	// reflection of the DemuxAdd[O](demux, node) function
	// This is set in the destination node instead of the source node
	// as we have the output type information only
	inputDemuxAdd reflect.Value
}

// Builder helps to build a graph and to connect their nodes. It takes care of instantiating all
// its stages given a name and a type, as well as connect them. If two connected stages have
// incompatible types, it will insert a codec in between to translate between the stage types
type Builder struct {
	// providers here are function that return StartFunc, MiddleFunc, TermFunc...
	// they are invoked first, then its returned values will be stored in startNodes, middleNodes, etc... attributes
	startProviders    map[reflect.Type]reflectedNode
	middleProviders   map[reflect.Type]reflectedNode
	terminalProviders map[reflect.Type]reflectedNode
	// a provider just for codecs
	codecs map[codecKey]reflectedNode
	// non-demuxed nodes
	// keys: instance IDs
	startNodes  map[string]outTyper
	middleNodes map[string]destinableInOutNode
	termNodes   map[string]destinableInNode
	// demuxed nodes that do not directly implement outTyper but node.Demuxed
	startDemuxedNodes  map[string]node.Demuxed
	middleDemuxedNodes map[string]reflectedDemuxedNode

	options []reflect.Value
	// used to check unconnected nodes
	inNodeNames  map[string]struct{}
	outNodeNames map[string]struct{}
	// used to avoid failing a "sendTo" annotation pointing to a disabled node
	disabledNodes map[string]struct{}
	// used to forward data from disabled Nodes
	// key: forwarder node IDs, value: destinations of that forwarder
	forwarderNodes map[string][]dstConnector
}

// NewBuilder instantiates a Graph Builder with the default configuration, which can be overridden via the
// arguments.
func NewBuilder(options ...node.Option) *Builder {
	optVals := make([]reflect.Value, 0, len(options))
	for _, opt := range options {
		optVals = append(optVals, reflect.ValueOf(opt))
	}
	return &Builder{
		codecs:             map[codecKey]reflectedNode{},
		startProviders:     map[reflect.Type]reflectedNode{}, // stage.StartProvider
		middleProviders:    map[reflect.Type]reflectedNode{}, // stage.MiddleProvider{},
		terminalProviders:  map[reflect.Type]reflectedNode{}, // stage.TerminalProvider{},
		startNodes:         map[string]outTyper{},            // *node.Start
		middleNodes:        map[string]destinableInOutNode{}, // *node.Middle
		termNodes:          map[string]destinableInNode{},    // *node.Terminal
		startDemuxedNodes:  map[string]node.Demuxed{},
		middleDemuxedNodes: map[string]reflectedDemuxedNode{},
		options:            optVals,
		inNodeNames:        map[string]struct{}{},
		outNodeNames:       map[string]struct{}{},
		disabledNodes:      map[string]struct{}{},
		forwarderNodes:     map[string][]dstConnector{},
	}
}

// RegisterCodec registers a Codec into the graph builder. A Codec is a node.MiddleFunc provider
// that allows converting data types and it's automatically inserted when a node with a given
// output type is connected to a node with a different input type. When nodes with different
// types are connected, a codec converting between both MUST have been registered previously.
// Otherwise the graph Build method will fail.
func RegisterCodec[I, O any](nb *Builder, middleFunc node.MiddleFunc[I, O]) {
	var in I
	var out O
	// temporary middle node used only to check input/output types
	nb.codecs[codecKey{In: reflect.TypeOf(in), Out: reflect.TypeOf(out)}] = reflectedNode{
		instancer: reflect.ValueOf(node.AsMiddle[I, O]),
		provider:  reflect.ValueOf(middleFunc),
	}
}

// RegisterStart registers a stage.StartProvider into the graph builder. When the Build
// method is invoked later, any configuration field associated with the StartProvider will
// result in the instantiation of a node.Start with the provider's returned provider.
// The passed configuration type must either implement the stage.Instancer interface or the
// configuration struct containing it must define a `nodeId` tag with an identifier for that stage.
func RegisterStart[CFG, O any](nb *Builder, b stage.StartProvider[CFG, O]) {
	nb.startProviders[typeOf[CFG]()] = reflectedNode{
		instancer: reflect.ValueOf(node.AsStart[O]),
		provider:  reflect.ValueOf(b),
	}
}

// RegisterMultiStart is similar to RegisterStart, but registers a stage.StartMultiProvider,
// which allows associating multiple functions with a single node
func RegisterMultiStart[CFG, O any](nb *Builder, b stage.StartMultiProvider[CFG, O]) {
	nb.startProviders[typeOf[CFG]()] = reflectedNode{
		instancer: reflect.ValueOf(node.AsStart[O]),
		provider:  reflect.ValueOf(b),
	}
}

// RegisterMiddle registers a stage.MiddleProvider into the graph builder. When the Build
// method is invoked later, any configuration field associated with the MiddleProvider will
// result in the instantiation of a node.Middle with the provider's returned provider.
// The passed configuration type must either implement the stage.Instancer interface or the
// configuration struct containing it must define a `nodeId` tag with an identifier for that stage.
func RegisterMiddle[CFG, I, O any](nb *Builder, b stage.MiddleProvider[CFG, I, O]) {
	nb.middleProviders[typeOf[CFG]()] = reflectedNode{
		instancer: reflect.ValueOf(node.AsMiddle[I, O]),
		provider:  reflect.ValueOf(b),
		// even if we don't know if the node will receive information from a Demux
		// we need to store the function reference just in case
		inputDemuxAdd: reflect.ValueOf(node.DemuxAdd[I]),
	}
}

// RegisterTerminal registers a stage.TerminalProvider into the graph builder. When the Build
// method is invoked later, any configuration field associated with the TerminalProvider will
// result in the instantiation of a node.Terminal with the provider's returned provider.
// The passed configuration type must either implement the stage.Instancer interface or the
// configuration struct containing it must define a `nodeId` tag with an identifier for that stage.
func RegisterTerminal[CFG, I any](nb *Builder, b stage.TerminalProvider[CFG, I]) {
	nb.terminalProviders[typeOf[CFG]()] = reflectedNode{
		instancer: reflect.ValueOf(node.AsTerminal[I]),
		provider:  reflect.ValueOf(b),
		// even if we don't know if the node will receive information from a Demux
		// we need to store the function reference just in case
		inputDemuxAdd: reflect.ValueOf(node.DemuxAdd[I]),
	}
}

// Build creates a Graph where each node corresponds to a field in the provided Configuration struct.
// The nodes will be connected according to any of the following alternatives:
//   - The ConnectedConfig "source" --> ["destination"...] map, if the passed type implements ConnectedConfig interface.
//   - The sendTo annotations on each graph stage.
func (b *Builder) Build(cfg any) (Graph, error) {
	g := Graph{}
	if err := b.applyConfig(cfg); err != nil {
		return g, err
	}

	for _, i := range b.startNodes {
		g.start = append(g.start, i.(startNode))
	}
	for _, i := range b.startDemuxedNodes {
		g.start = append(g.start, i.(startNode))
	}
	for _, e := range b.termNodes {
		g.terms = append(g.terms, e.node.(terminalNode))
	}

	// validate that there aren't nodes without connection
	if len(b.outNodeNames) > 0 {
		names := make([]string, 0, len(b.outNodeNames))
		for n := range b.outNodeNames {
			names = append(names, n)
		}
		return g, fmt.Errorf("the following nodes don't have any output: %s",
			strings.Join(names, ", "))
	}
	if len(b.inNodeNames) > 0 {
		names := make([]string, 0, len(b.inNodeNames))
		for n := range b.inNodeNames {
			names = append(names, n)
		}
		return g, fmt.Errorf("the following nodes don't have any input: %s",
			strings.Join(names, ", "))
	}

	return g, nil
}

func (nb *Builder) instantiate(instanceID string, arg reflect.Value) error {
	// TODO: check if instanceID is duplicate
	if instanceID == "" {
		return fmt.Errorf("instance ID for type %s can't be empty", arg.Type())
	}
	rargs := []reflect.Value{
		arg, // arg 0: configuration value
	}
	if ib, ok := nb.startProviders[arg.Type()]; ok {
		return nb.instantiateStart(instanceID, ib, rargs)
	}
	if tb, ok := nb.middleProviders[arg.Type()]; ok {
		return nb.instantiateMiddle(instanceID, tb, rargs)
	}

	if eb, ok := nb.terminalProviders[arg.Type()]; ok {
		return nb.instantiateTerminal(instanceID, eb, rargs)
	}
	return fmt.Errorf("for node ID: %q. Provider not registered for type %q", instanceID, arg.Type())
}

func (nb *Builder) instantiateStart(instanceID string, ib reflectedNode, rargs []reflect.Value) error {
	// providedFunc, err = StartProvider(arg)
	callResult := ib.provider.Call(rargs)
	providedFunc := callResult[0]
	errVal := callResult[1]

	if !errVal.IsNil() || !errVal.IsZero() {
		return fmt.Errorf("instantiating start instance %q: %w", instanceID, errVal.Interface().(error))
	}

	// If the providedFunc is a slice of funcs, it means we need to call AsStart as a variadic Function
	var startNode []reflect.Value
	if providedFunc.Kind() == reflect.Slice {
		// startNode = AsStart(providedFuncs...)
		startNode = ib.instancer.CallSlice([]reflect.Value{providedFunc})
	} else {
		// startNode = AsStart(providedFunc)
		startNode = ib.instancer.Call([]reflect.Value{providedFunc})
	}
	if ib.demuxed {
		nb.startDemuxedNodes[instanceID] = startNode[0].Interface().(node.Demuxed)
	} else {
		nb.startNodes[instanceID] = startNode[0].Interface().(outTyper)
	}
	nb.outNodeNames[instanceID] = struct{}{}
	return nil
}

func (nb *Builder) instantiateMiddle(instanceID string, tb reflectedNode, rargs []reflect.Value) error {
	// providedFunc, err = MiddleProvider(arg)
	callResult := tb.provider.Call(rargs)
	providedFunc := callResult[0]
	errVal := callResult[1]

	if !errVal.IsNil() || !errVal.IsZero() {
		return fmt.Errorf("instantiating middle instance %q: %w", instanceID, errVal.Interface().(error))
	}

	// middleNode = AsMiddle(providedFunc, nb.options...)
	middleNode := tb.instancer.Call(append([]reflect.Value{providedFunc}, nb.options...))
	if tb.demuxed {
		mn := middleNode[0].Interface().(inDemuxedOutTyper)
		nb.middleDemuxedNodes[instanceID] = reflectedDemuxedNode{
			node:          mn,
			inputDemuxAdd: tb.inputDemuxAdd,
			demuxed:       mn,
		}
	} else {
		nb.middleNodes[instanceID] = destinableInOutNode{
			node:          middleNode[0].Interface().(inOutTyper),
			inputDemuxAdd: tb.inputDemuxAdd,
		}
	}
	nb.inNodeNames[instanceID] = struct{}{}
	nb.outNodeNames[instanceID] = struct{}{}
	return nil
}

func (nb *Builder) instantiateTerminal(instanceID string, eb reflectedNode, rargs []reflect.Value) error {
	// providedFunc, err = TerminalProvider(arg)
	callResult := eb.provider.Call(rargs)
	providedFunc := callResult[0]
	errVal := callResult[1]

	if !errVal.IsNil() || !errVal.IsZero() {
		return fmt.Errorf("instantiating terminal instance %q: %w", instanceID, errVal.Interface().(error))
	}

	// termNode = AsTerminal(providedFunc, nb.options...)
	termNode := eb.instancer.Call(append([]reflect.Value{providedFunc}, nb.options...))
	nb.termNodes[instanceID] = destinableInNode{
		node:          termNode[0].Interface().(inTyper),
		inputDemuxAdd: eb.inputDemuxAdd,
	}
	nb.inNodeNames[instanceID] = struct{}{}
	return nil
}

func (b *Builder) connect(src string, dst dstConnector) error {
	if src == dst.dstNode {
		return fmt.Errorf("node %q must not send data to itself", dst.dstNode)
	}
	// remove the src and dst from the inNodeNames and outNodeNames to mark that
	// they have been already connected
	delete(b.inNodeNames, dst.dstNode)
	delete(b.outNodeNames, src)
	// Ignore disabled nodes, as they are disabled by the user
	// despite the connection is hardcoded in the nodeId, sendTo tags
	if _, ok := b.disabledNodes[src]; ok {
		return nil
	}
	if _, ok := b.disabledNodes[dst.dstNode]; ok {
		// if the disabled destination is configured to forward data, it will recursively
		// connect the source with its own destinations
		if fwds, ok := b.forwarderNodes[dst.dstNode]; ok {
			for _, fwdDst := range fwds {
				// if the source is demuxed, we need to forward the source demux info
				// instead of the destination demux
				dstWithSrcDemux := dstConnector{demuxChan: dst.demuxChan, dstNode: fwdDst.dstNode}
				if err := b.connect(src, dstWithSrcDemux); err != nil {
					return err
				}
			}
		}
		return nil
	}

	// find source and destination stages
	var srcDemuxedNode node.Demuxed
	srcNode, ok := b.getSrcNode(src)
	if !ok {
		srcDemuxedNode, ok = b.getSrcDemuxedNode(src)
		if !ok {
			return fmt.Errorf("invalid source node: %q", src)
		}
	}
	dstNode, ok := b.getDstNode(dst.dstNode)
	if !ok {
		return fmt.Errorf("invalid destination node: %q", dst.dstNode)
	}
	if srcNode != nil {
		return b.directConnection(src, dst, srcNode, dstNode)
	} else {
		return b.demuxedConnection(src, dst, srcDemuxedNode, dstNode)
	}
}

func (b *Builder) directConnection(srcName string, dstName dstConnector, srcNode outTyper, dstNode reflectedDemuxedNode) error {
	if dstName.demuxChan != "" {
		return fmt.Errorf("node %q has no demuxed output. Its destination node name can't have the '%s:' prefix (%s:%s)",
			srcName, dstName.demuxChan, dstName.demuxChan, dstName.dstNode)
	}
	srcSendsToMethod := reflect.ValueOf(srcNode).MethodByName("SendTo")
	if srcSendsToMethod.IsZero() {
		panic(fmt.Sprintf("BUG: for stage %q, source of type %T does not have SendTo method", srcName, srcNode))
	}
	// check if they have compatible types
	if srcNode.OutType() == dstNode.node.InType() {
		srcSendsToMethod.Call([]reflect.Value{reflect.ValueOf(dstNode.node)})
		return nil
	}
	// otherwise, we will add in intermediate codec layer
	codec, ok := b.newCodec(srcNode.OutType(), dstNode.node.InType())
	if !ok {
		// TODO: this is not tested
		return fmt.Errorf("can't connect %q and %q stages because there isn't registered"+
			" any %s -> %s codec", srcName, dstName, srcNode.OutType(), dstNode.node.InType())
	}
	srcSendsToMethod.Call([]reflect.Value{codec})
	codecSendsToMethod := codec.MethodByName("SendTo")
	if codecSendsToMethod.IsZero() {
		panic(fmt.Sprintf("BUG: for stage %q, codec of type %T does not have SendTo method", srcName, srcNode))
	}
	codecSendsToMethod.Call([]reflect.Value{reflect.ValueOf(dstNode.node)})
	return nil
}

func (b *Builder) demuxedConnection(src string, dstName dstConnector, srcNode node.Demuxed, dstNode reflectedDemuxedNode) error {
	if dstName.demuxChan == "" {
		return fmt.Errorf("node %q has demuxed output. Its destination node name must have a named output prefix (for example out1:%s)",
			src, dstName.dstNode)
	}

	// demux := DemuxAdd[outType](srcNode, "chanName")
	reflectedDemux := dstNode.inputDemuxAdd.Call([]reflect.Value{reflect.ValueOf(srcNode), reflect.ValueOf(dstName.demuxChan)})

	// check if the output of the demux is compatible with the input of the connected node
	demuxOutType := reflectedDemux[0].Interface().(outTyper).OutType()
	if demuxOutType != dstNode.node.InType() {
		// in principle, this should never happen as the demuxOutType is created from the dstNode type
		return fmt.Errorf("can't connect %s and %s:%s stages because the output %s (type %s) does not match"+
			" the input of the node %s (type %s)", src, dstName.demuxChan, dstName.dstNode, dstName.demuxChan,
			demuxOutType.String(), dstName.dstNode, dstNode.node.InType().String())
	}

	// demux.SendTo(dstNode)
	reflectedDemux[0].MethodByName("SendTo").Call([]reflect.Value{reflect.ValueOf(dstNode.node)})

	return nil
}

// returns a node.Midle[?, ?] as a value
func (b *Builder) newCodec(inType, outType reflect.Type) (reflect.Value, bool) {
	codec, ok := b.codecs[codecKey{In: inType, Out: outType}]
	if !ok {
		return reflect.ValueOf(nil), false
	}

	result := codec.instancer.Call([]reflect.Value{codec.provider})
	return result[0], true
}

func typeOf[T any]() reflect.Type {
	var t T
	return reflect.TypeOf(t)
}

func (b *Builder) getSrcNode(id string) (outTyper, bool) {
	if srcNode, ok := b.startNodes[id]; ok {
		return srcNode, true
	}
	if srcNode, ok := b.middleNodes[id]; ok {
		return srcNode.node, true
	}
	return nil, false
}

func (b *Builder) getSrcDemuxedNode(id string) (node.Demuxed, bool) {
	if srcNode, ok := b.startDemuxedNodes[id]; ok {
		return srcNode, true
	}
	if srcNode, ok := b.middleDemuxedNodes[id]; ok {
		return srcNode.demuxed, true
	}
	return nil, false
}

func (b *Builder) getDstNode(id string) (reflectedDemuxedNode, bool) {
	if dstNode, ok := b.middleNodes[id]; ok {
		return reflectedDemuxedNode{
			node:          dstNode.node,
			inputDemuxAdd: dstNode.inputDemuxAdd,
		}, true
	}
	if dstNode, ok := b.middleDemuxedNodes[id]; ok {
		return reflectedDemuxedNode{
			node:          dstNode.node,
			inputDemuxAdd: dstNode.inputDemuxAdd,
		}, true
	}
	if dstNode, ok := b.termNodes[id]; ok {
		return reflectedDemuxedNode{
			node:          dstNode.node,
			inputDemuxAdd: dstNode.inputDemuxAdd,
		}, true
	}
	return reflectedDemuxedNode{}, false
}
