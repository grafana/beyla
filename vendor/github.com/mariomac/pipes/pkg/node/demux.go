package node

import (
	"fmt"
	"reflect"

	"github.com/mariomac/pipes/pkg/node/internal/connect"
)

// Demuxed node whose output is not a channel but a Demux.
// Can be both StartDemux or MiddleDemux nodes
// Experimental API. Some names could change in the following versions.
type Demuxed interface {
	demuxBuilder() *demuxBuilder
}

// Demux is a collection of multiple output channels for a
// Demuxed node, which receives them as a second argument in its
// StartDemuxFunc or MiddleDemuxFunc functions.
// During the graph definition time, multiple outputs can be
// associated to a node by means of the DemuxAdd function.
// At runtime, you can access the multiple named output
// channels by means of the DemuxGet function.
// Experimental API. Some names could change in the following versions.
type Demux struct {
	// Key: the key/name of the output
	outChans map[any]any
}

// StartDemuxFunc is a function that receives a Demux as unique argument,
// and sends, during an indefinite amount of time, values to the channels
// contained in the Demux (previously accessed by the DemuxGet function).
// Experimental API. Some names could change in the following versions.
type StartDemuxFunc func(out Demux)

// MiddleDemuxFunc is a function that receives a readable channel as first argument,
// and a Demux as second argument.
// It must process the inputs from the input channel until it's closed
// and usually forward the processed values to any of the Demux output channels
// (previously accessed by the DemuxGet function).
// Experimental API. Some names could change in the following versions.
type MiddleDemuxFunc[IN any] func(in <-chan IN, out Demux)

// demuxBuilder is an accessory object to define, during the construction time,
// the multiple outputs of a demuxed node
type demuxBuilder struct {
	// key: any value of any type, to identify the connection output
	// value: reflect.ValueOf(&receiverGroup[OUT])
	outNodes map[any]reflect.Value
}

// demuxOut provides reflection access to the value of a receiverGroup pointer
// Their methods are equivalent to receiverGroup but using reflection access
// to avoid compile-time check of generics
type demuxOut[OUT any] struct {
	reflectOut reflect.Value // reflect.ValueOf(&receiverGroup[OUT])
}

func (do *demuxOut[OUT]) OutType() reflect.Type {
	var out OUT
	return reflect.TypeOf(out)
}

func (do *demuxOut[OUT]) SendTo(outs ...Receiver[OUT]) {
	for _, out := range outs {
		// above block is equivalent to
		// receiverGroup.Outs = append(receiverGroup.Outs, out)
		outSlice := do.reflectOut.Elem().FieldByName("Outs")
		outSlice.Grow(1)
		outSlice.SetLen(outSlice.Cap())
		outSlice.Index(outSlice.Cap() - 1).Set(reflect.ValueOf(out))
	}
}

// DemuxAdd is used during the graph definition/construction time.
// It allows associating multiple output paths to a Demuxed node
// (which can be StartDemux or MiddleDemux). It returns a Sender
// output that can be connected to a group of output nodes for that
// path.
// The Sender created output is
// identified by a key that can be any value of any type, and
// can be later accessed from inside the node's StartDemuxFunc or
// MiddleDemuxFunc with the DemuxGet function.
// Experimental API. Some names could change in the following versions.
func DemuxAdd[OUT any](d Demuxed, key any) Sender[OUT] {
	demux := d.demuxBuilder()
	var out OUT
	to := reflect.TypeOf(out)
	outNod, ok := demux.outNodes[key]
	if !ok {
		outNod = reflect.ValueOf(&receiverGroup[OUT]{outType: to})
		demux.outNodes[key] = outNod
	}

	return &demuxOut[OUT]{reflectOut: outNod}
}

// DemuxGet returns the output channel associated to the given key
// in the provided Demux.
// This function needs to be invoked inside a StartDemuxFunc or
// MiddleDemuxFunc.
// The function will panic if no output channel has been previously
// defined at build time for that given key (using the DemuxAdd) function.
// Experimental API. Some names could change in the following versions.
func DemuxGet[OUT any](d Demux, key any) chan<- OUT {
	if on, ok := d.outChans[key]; !ok {
		panic(fmt.Sprintf("Demux has not registered any sender for key %#v", key))
	} else {
		return on.(chan OUT)
	}
}

// StartDemux is equivalent to a Start node, but receiving a Demux instead
// of a writable channel.
// Start nodes are the starting points of a graph. This is, all the nodes that bring information
// from outside the graph: e.g. because they generate them or because they acquire them from an
// external source like a Web Service.
// A graph must have at least one Start or StartDemux node.
// A StartDemux node must have at least one output node.
// Experimental API. Some names could change in the following versions.
type StartDemux struct {
	demux demuxBuilder
	funs  []StartDemuxFunc
}

// AsStartDemux wraps a group of StartDemuxFunc into a StartDemux node.
func AsStartDemux(funs ...StartDemuxFunc) *StartDemux {
	return &StartDemux{
		funs: funs,
	}
}

func (i *StartDemux) demuxBuilder() *demuxBuilder {
	if i.demux.outNodes == nil {
		i.demux.outNodes = map[any]reflect.Value{}
	}
	return &i.demux
}

// Start starts the function wrapped in the StartDemux node. This method should be invoked
// for all the start nodes of the same graph, so the graph can properly start and finish.
func (i *StartDemux) Start() {
	releasers, demux := startAndCollectReleaseFuncs(i)

	// Invocation to all the start node functions, with
	// deferred invocation to the ReleaseSender methods that were previously collected
	for fn := range i.funs {
		fun := i.funs[fn]
		go func() {
			defer func() {
				for _, release := range releasers {
					release.Call(nil)
				}
			}()
			fun(demux)
		}()
	}
}

// for any demuxed node, starts the receivers and collects the released
// nodes. It also returns a demux with the connections to the receiver
// nodes.
func startAndCollectReleaseFuncs(d Demuxed) ([]reflect.Value, Demux) {
	db := d.demuxBuilder()
	if len(db.outNodes) == 0 {
		panic(fmt.Sprintf("Demux in the node of type %T should define at least one output", d))
	}
	// TODO: panic if no outputs?
	releasers := make([]reflect.Value, 0, len(db.outNodes))
	demux := Demux{outChans: map[any]any{}}
	for k, on := range db.outNodes {
		// forker, err := on.StartReceivers()
		method := on.MethodByName("StartReceivers")
		startResult := method.Call(nil)
		// if err != nil {
		if !startResult[1].IsNil() {
			panic(fmt.Sprintf("%T node %s: %s", d, k, startResult[1].Interface()))
		}
		// outChans[k] = forker.AcquireSender()
		forker := startResult[0]
		demux.outChans[k] = forker.MethodByName("AcquireSender").Call(nil)[0].Interface()
		// releasers = append(releasers, forker.ReleaseSender())
		releasers = append(releasers, forker.MethodByName("ReleaseSender"))
	}
	return releasers, demux
}

// MiddleDemux is any intermediate node that receives data from another node, processes/filters it,
// and forwards the data any of the output channels in the provided Demux.
// An MiddleDemux node must have at least one output node.
// Experimental API. Some names could change in the following versions.
type MiddleDemux[IN any] struct {
	fun    MiddleDemuxFunc[IN]
	demux  demuxBuilder
	inputs connect.Joiner[IN]
	// nolint:unused
	started bool
	inType  reflect.Type
}

// AsMiddleDemux wraps an MiddleDemuxFunc into an MiddleDemux node.
// Experimental API. Some names could change in the following versions.
func AsMiddleDemux[IN any](fun MiddleDemuxFunc[IN], opts ...Option) *MiddleDemux[IN] {
	var in IN
	options := getOptions(opts...)
	return &MiddleDemux[IN]{
		inputs: connect.NewJoiner[IN](options.channelBufferLen),
		fun:    fun,
		inType: reflect.TypeOf(in),
	}
}

// nolint:unused
func (m *MiddleDemux[IN]) joiner() *connect.Joiner[IN] {
	return &m.inputs
}

// nolint:unused
func (m *MiddleDemux[IN]) isStarted() bool {
	return m.started
}

func (m *MiddleDemux[IN]) InType() reflect.Type {
	return m.inType
}

// nolint:unused
func (m *MiddleDemux[IN]) start() {
	releasers, demux := startAndCollectReleaseFuncs(m)

	go func() {
		defer func() {
			for _, release := range releasers {
				release.Call(nil)
			}
		}()
		m.fun(m.inputs.Receiver(), demux)
	}()
}

func (i *MiddleDemux[IN]) demuxBuilder() *demuxBuilder {
	if i.demux.outNodes == nil {
		i.demux.outNodes = map[any]reflect.Value{}
	}
	return &i.demux
}
