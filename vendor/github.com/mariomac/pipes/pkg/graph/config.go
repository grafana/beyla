package graph

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/mariomac/pipes/pkg/graph/stage"
)

var connectorType = reflect.TypeOf(Connector{})
var graphInstanceType = reflect.TypeOf(stage.Instance(""))

// Connector is a convenience implementor of the ConnectedConfig interface, required
// to build any graph. It can be embedded into any configuration struct that is passed
// as argument into the builder.Build method.
//
// Key: instance ID of the source node. Value: array of destination node instance IDs.
type Connector map[string][]string

// Connections returns the connection map represented by the Connector
func (c Connector) Connections() map[string][]string {
	return c
}

// ConnectedConfig describes the interface that any struct passed to the builder.Build
// method must fullfill. Consider embedding the Connector type into your struct for
// automatic implementation of the interface.
type ConnectedConfig interface {
	// Connections returns a map representing the connection of the node graphs, where
	// the key contains the instance ID of the source node, and the value contains an
	// array of the destination nodes' instance IDs.
	Connections() map[string][]string
}

// applyConfig instantiates and configures the different pipeline stages according to the provided configuration
func (b *Builder) applyConfig(cfg any) error {
	annotatedConnections := map[string][]string{}
	cv := reflect.ValueOf(cfg)
	if cv.Kind() == reflect.Pointer {
		if err := b.applyConfigReflect(cv.Elem(), annotatedConnections); err != nil {
			return err
		}
	} else {
		if err := b.applyConfigReflect(cv, annotatedConnections); err != nil {
			return err
		}
	}

	// connect any node with the sendTo annotation
	for src, dsts := range annotatedConnections {
		for _, dst := range dsts {
			if err := b.connect(src, dst); err != nil {
				return err
			}
		}
	}

	// Connections() implementation will override any `sendTo` annotation. But both can coexist
	ccfg, ok := cfg.(ConnectedConfig)
	if !ok {
		return nil
	}
	for src, dsts := range ccfg.Connections() {
		for _, dst := range dsts {
			if err := b.connect(src, dst); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *Builder) applyConfigReflect(cfgValue reflect.Value, conns map[string][]string) error {
	if cfgValue.Kind() != reflect.Struct {
		return fmt.Errorf("configuration should be a struct. Was: %s", cfgValue.Type())
	}
	valType := cfgValue.Type()
	for f := 0; f < valType.NumField(); f++ {
		field := valType.Field(f)
		if field.Type == connectorType {
			continue
		}
		fieldVal := cfgValue.Field(f)
		if fieldVal.Type().Kind() == reflect.Array || fieldVal.Type().Kind() == reflect.Slice {
			if err := b.applyArrayOrSlice(field, fieldVal, conns); err != nil {
				return err
			}
		} else {
			if err := b.applyField(field, cfgValue.Field(f), conns); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *Builder) applyArrayOrSlice(field reflect.StructField, fieldVal reflect.Value, conns map[string][]string) error {
	// If the array type is tagged as a single node, apply it as a normal field
	// ignoring error as it is possible that an array doesn't have any instanceID but its subnodes
	if instanceID, _ := b.instanceID(field, fieldVal); instanceID != "" {
		return b.applyField(field, fieldVal, conns)
	}
	// otherwise, try to apply its elements one by one
	for nf := 0; nf < fieldVal.Len(); nf++ {
		if err := b.applyField(field, fieldVal.Index(nf), conns); err != nil {
			return err
		}
	}
	return nil
}

// applies the field given an ID in the following order (from high priority to overridable lower):
// 1- The result of the ID() method if the configuration implements stage.Instancer
// 2- The ID specified by the stage.Instance embedded type, if any
// 3- The result of the `nodeId` embedded tag in the struct
// otherwise it throws a runtime error
func (b *Builder) applyField(fieldType reflect.StructField, fieldVal reflect.Value, conns map[string][]string) error {
	instanceID, err := b.instanceID(fieldType, fieldVal)
	if err != nil {
		return err
	}
	if instanceID == nodeIdIgnore {
		return nil
	}

	// checks if it has a sendTo annotation and update the connections map accordingly
	if dstNode, ok := fieldType.Tag.Lookup(sendsToTag); ok {
		conns[instanceID] = strings.Split(dstNode, ",")
	} else {
		b.checkForwarding(fieldType, conns, instanceID)
	}

	// Ignore the config field if it is not enabled
	if !isEnabled(fieldVal) {
		b.disabledNodes[instanceID] = struct{}{}
		return nil
	}

	return b.instantiate(instanceID, fieldVal)
}

func (b *Builder) instanceID(fieldType reflect.StructField, fieldVal reflect.Value) (string, error) {
	if instancer, ok := fieldVal.Interface().(stage.Instancer); ok {
		return instancer.ID(), nil
		//	// if it does not implement the instancer interface, let's check if it can be converted
		//	// to the convenience stage.Instance type
		//	// TODO: if it implements it as a pointer but it is a value, try getting a pointer as we do later with Enabler
		//	instanceID = fieldVal.Convert(graphInstanceType).Interface().(stage.Instance).ID()
	}
	// Otherwise, let's check for the nodeId embedded tag in the struct if any
	if instanceID, ok := fieldType.Tag.Lookup(nodeIdTag); ok {
		return instanceID, nil
	}
	// But fail if it is not possible
	return "", fmt.Errorf("field of type %s should provide an 'ID() InstanceID' method or be tagged"+
		" with a `nodeId` tag in the configuration struct. Please provide a `nodeId` tag or e.g."+
		" embed the stage.Instance field", fieldVal.Type())
}

// updates the connections and forwarding connections in case the field is marked as forwardTo
func (b *Builder) checkForwarding(fieldType reflect.StructField, conns map[string][]string, instanceID string) {
	if dstNode, ok := fieldType.Tag.Lookup(fwdToTag); ok {
		dsts := strings.Split(dstNode, ",")
		conns[instanceID] = dsts
		b.forwarderNodes[instanceID] = dsts
	}
}

// A node value is disabled if it's a nil pointer, an nil slice, or implements stage.Enabler and returns false
func isEnabled(val reflect.Value) bool {
	enabler, ok := val.Interface().(stage.Enabler)
	// In case the implementation receiver is a value but the field is a pointer, we
	// try also with the value
	if !ok && val.Kind() == reflect.Pointer && !val.IsZero() {
		enabler, ok = val.Elem().Interface().(stage.Enabler)
	}
	if ok {
		return enabler.Enabled()
	}
	slice := val.Kind() == reflect.Slice
	nillable := val.Kind() == reflect.Pointer || slice
	return slice && val.Len() > 0 || !nillable || !val.IsNil()
}
