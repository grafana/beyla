package graph

import (
	"fmt"
	"reflect"

	"github.com/mariomac/pipes/pkg/graph/stage"
)

var connectorType = reflect.TypeOf(Connector{})

// Connector is a convenience implementor of the ConnectedConfig interface, required
// to build any graph. It can be embedded into any configuration struct that is passed
// as argument into the builder.Build method.
//
// Key: instance ID of the source node. Value: array of destination node instance IDs.
// Deprecated. Please use the low-level API of this library as this will be removed in future versions.
type Connector map[string][]string

// Connections returns the connection map represented by the Connector
func (c Connector) Connections() map[string][]string {
	return c
}

// ConnectedConfig describes the interface that any struct passed to the builder.Build
// method must fullfill. Consider embedding the Connector type into your struct for
// automatic implementation of the interface.
// Deprecated. Please use the low-level API of this library as this will be removed in future versions.
type ConnectedConfig interface {
	// Connections returns a map representing the connection of the node graphs, where
	// the key contains the instance ID of the source node, and the value contains an
	// array of the destination nodes' instance IDs.
	Connections() map[string][]string
}

// applyConfig instantiates and configures the different pipeline stages according to the provided configuration
func (nb *Builder) applyConfig(cfg any) error {
	annotatedConnections := map[string][]dstConnector{}
	cv := reflect.ValueOf(cfg)
	if cv.Kind() == reflect.Pointer {
		if err := nb.applyConfigReflect(cv.Elem(), annotatedConnections); err != nil {
			return err
		}
	} else {
		if err := nb.applyConfigReflect(cv, annotatedConnections); err != nil {
			return err
		}
	}

	// connect any node with the sendTo annotation
	for src, dsts := range annotatedConnections {
		for _, dst := range dsts {
			if err := nb.connect(src, dst); err != nil {
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
			dstC := connectorFrom(dst)
			if err := nb.connect(src, dstC); err != nil {
				return err
			}
		}
	}
	return nil
}

func (nb *Builder) applyConfigReflect(cfgValue reflect.Value, conns map[string][]dstConnector) error {
	if cfgValue.Kind() != reflect.Struct {
		return fmt.Errorf("configuration should be a struct. Was: %s", cfgValue.Type())
	}
	valType := cfgValue.Type()
	for f := 0; f < valType.NumField(); f++ {
		field := valType.Field(f)
		if field.Type == connectorType {
			continue
		}
		if err := nb.applyField(field, cfgValue.Field(f), conns); err != nil {
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
func (nb *Builder) applyField(fieldType reflect.StructField, fieldVal reflect.Value, conns map[string][]dstConnector) error {
	instanceID, err := nb.instanceID(fieldType, fieldVal)
	if err != nil {
		return err
	}
	if instanceID == nodeIdIgnore {
		return nil
	}

	// checks if it has a sendTo annotation and update the connections map accordingly
	if sendsTo, ok := fieldType.Tag.Lookup(sendsToTag); ok {
		conns[instanceID] = allConnectorsFrom(sendsTo)
	} else {
		nb.checkForwarding(fieldType, conns, instanceID)
	}

	// Ignore the config field if it is not enabled
	if !isEnabled(fieldVal) {
		nb.disabledNodes[instanceID] = struct{}{}
		return nil
	}

	return nb.instantiate(instanceID, fieldVal)
}

func (nb *Builder) instanceID(fieldType reflect.StructField, fieldVal reflect.Value) (string, error) {
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
	// Otherwise, let's get the struct field name
	if fieldType.Name != "" {
		return fieldType.Name, nil
	}

	// But fail if it is not possible
	return "", fmt.Errorf("can't get an instance ID for the field of type %s. Please"+
		" provide an 'ID() InstanceID' method for the type, or tag the field"+
		" with a `nodeId` tag in the configuration struct, or just use a field with a Name",
		fieldVal.Type())
}

// updates the connections and forwarding connections in case the field is marked as forwardTo
func (nb *Builder) checkForwarding(fieldType reflect.StructField, conns map[string][]dstConnector, instanceID string) {
	if fwdToContent, ok := fieldType.Tag.Lookup(fwdToTag); ok {
		dsts := allConnectorsFrom(fwdToContent)
		conns[instanceID] = dsts
		nb.forwarderNodes[instanceID] = dsts
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
