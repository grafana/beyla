// This code is a derivation made by Grafana Labs, from the
// original source from IBM/RedHat under Apache 2.0 License
// https://github.com/netobserv/netobserv-ebpf-agent

package netflow

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/vmware/go-ipfix/pkg/entities"
	"github.com/vmware/go-ipfix/pkg/exporter"
	"github.com/vmware/go-ipfix/pkg/registry"

	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/components/pipe/global"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"

	"github.com/grafana/beyla/v2/pkg/beyla"
)

func ilog() *slog.Logger {
	return slog.With("component", "exporter/IPFIXProto")
}

// TODO: add support to IPv6
type netFlowExporter struct {
	log          *slog.Logger
	input        <-chan []*ebpf.Record
	v4template   uint16
	v4Attributes netFlowAttributes
	v6template   uint16
	v6Attributes netFlowAttributes
	exporter     *exporter.ExportingProcess
}

func Exporter(
	ctxInfo *global.ContextInfo,
	cfg *beyla.Config,
	input *msg.Queue[[]*ebpf.Record],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		log := ilog()
		log.Debug("instantiating NetFlow exporter",
			"collectorAddress", cfg.NetFlowExport.CollectorAddress,
			"collectorTransport", cfg.NetFlowExport.CollectorTransport)

		registry.LoadRegistry()

		exporter, err := exporter.InitExportingProcess(exporter.ExporterInput{
			CollectorAddress:    cfg.NetFlowExport.CollectorAddress,
			CollectorProtocol:   cfg.NetFlowExport.CollectorTransport,
			ObservationDomainID: 1,
			TempRefTimeout:      1,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize NetFlow exporter: %w", err)
		}

		exp := &netFlowExporter{
			log:      ilog(),
			input:    input.Subscribe(msg.SubscriberName("netflow.Exporter")),
			exporter: exporter,
		}
		attrProv, err := attributes.NewAttrSelector(ctxInfo.MetricAttributeGroups, &attributes.SelectorConfig{
			SelectionCfg:            cfg.Attributes.Select,
			ExtraGroupAttributesCfg: cfg.Attributes.ExtraGroupAttributes,
		})
		if err != nil {
			return nil, fmt.Errorf("process OTEL exporter attributes: %w", err)
		}
		attrNames := attrProv.For(attributes.NetworkFlow)

		exp.v4template = exporter.NewTemplateID()
		exp.v4Attributes = exp.netFlowAttributeGetters(attrNames, true)
		if err := addTemplateSet(exporter, exp.v4template, exp.v4Attributes); err != nil {
			return nil, fmt.Errorf("adding IPv4 template set: %w", err)
		}
		log.Debug("created NetFlow IPv4 template",
			"templateID", exp.v4template)

		exp.v6template = exporter.NewTemplateID()
		exp.v6Attributes = exp.netFlowAttributeGetters(attrNames, false)
		if err := addTemplateSet(exporter, exp.v6template, exp.v6Attributes); err != nil {
			return nil, fmt.Errorf("adding IPv6 template set: %w", err)
		}
		log.Debug("created NetFlow IPv6 template",
			"templateID", exp.v6template)

		return exp.doExport, nil
	}
}

func addTemplateSet(export *exporter.ExportingProcess, template uint16, attrs netFlowAttributes) error {
	templateSet := entities.NewSet(false)
	if err := templateSet.PrepareSet(entities.Template, template); err != nil {
		return err
	}
	if err := templateSet.AddRecord(attrs.entities, template); err != nil {
		return err
	}
	_, err := export.SendSet(templateSet)
	return err
}

// IPv6Type value as defined in IEEE 802: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
const IPv6Type = 0x86DD

func (e *netFlowExporter) doExport(ctx context.Context) {
	defer e.exporter.CloseConnToCollector()
	swarms.ForEachInput(ctx, e.input, e.log.Debug, func(flows []*ebpf.Record) {
		for _, flow := range flows {
			if flow.Id.EthProtocol == IPv6Type {
				e.exportIPv6(flow)
			} else {
				e.exportIPv4(flow)
			}
		}
	})
}

func (e *netFlowExporter) exportIPv6(fr *ebpf.Record) {
	dataSet := entities.NewSet(false)
	err := dataSet.PrepareSet(entities.Data, e.v6template)
	if err != nil {
		e.log.Error("failed to prepare NetFlow IPv6 dataSet", "error", err)
		return
	}
	// set values to the existing template
	for i, setter := range e.v6Attributes.setters {
		setter(fr, e.v6Attributes.entities[i])
	}
	// add record to dataset
	if err := dataSet.AddRecord(e.v6Attributes.entities, e.v6template); err != nil {
		e.log.Error("failed to add record to NetFlow IPv6 dataSet", "error", err)
		return
	}
	if _, err := e.exporter.SendSet(dataSet); err != nil {
		e.log.Error("failed to send NetFlow IPv6 dataSet", "error", err)
	}
}

func (e *netFlowExporter) exportIPv4(fr *ebpf.Record) {
	dataSet := entities.NewSet(false)
	err := dataSet.PrepareSet(entities.Data, e.v4template)
	if err != nil {
		e.log.Error("failed to prepare NetFlow IPv4 dataSet", "error", err)
		return
	}
	// set values to the existing template
	for i, setter := range e.v4Attributes.setters {
		setter(fr, e.v4Attributes.entities[i])
	}
	// add record to dataset
	if err := dataSet.AddRecord(e.v4Attributes.entities, e.v4template); err != nil {
		e.log.Error("failed to add record to NetFlow Ipv4 dataSet", "error", err)
		return
	}
	if _, err := e.exporter.SendSet(dataSet); err != nil {
		e.log.Error("failed to send NetFlow IPv4 dataSet", "error", err)
	}
}

func getElement(elementName string) (entities.InfoElementWithValue, error) {
	element, err := registry.GetInfoElement(elementName, registry.IANAEnterpriseID)
	if err != nil {
		return nil, fmt.Errorf("failed to get info element %s", elementName)
	}
	ie, err := entities.DecodeAndCreateInfoElementWithValue(element, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decode info element %s", elementName)
	}
	return ie, nil
}

// both entities and setters fields must be equal size and entities[n] must be set by setters[n]
type netFlowAttributes struct {
	entities []entities.InfoElementWithValue
	setters  []func(*ebpf.Record, entities.InfoElementWithValue)
}

func (e *netFlowExporter) netFlowAttributeGetters(attrDefs []attr.Name, ipv4 bool) netFlowAttributes {
	nfa := netFlowAttributes{
		entities: make([]entities.InfoElementWithValue, 0, len(attrDefs)),
		setters:  make([]func(*ebpf.Record, entities.InfoElementWithValue), 0, len(attrDefs)),
	}
	for _, name := range attrDefs {
		if err := addObiToNetFlowAttrName(name, ipv4, &nfa); err != nil {
			e.log.Warn("attribute not yet supported in NetFlow exporter", "attribute", name, "error", err)
		}
	}
	return nfa
}

func attrNameToEntityName(name attr.Name, ipv4 bool) string {
	switch name {
	case attr.Transport:
		return "protocolIdentifier"
	case attr.SrcAddress:
		if ipv4 {
			return "sourceIPv4Address"
		} else {
			return "sourceIPv6Address"
		}
	case attr.DstAddres:
		if ipv4 {
			return "destinationIPv4Address"
		} else {
			return "destinationIPv6Address"
		}
	case attr.SrcPort:
		return "sourceTransportPort"
	case attr.DstPort:
		return "destinationTransportPort"
	case attr.IfaceDirection:
		return "flowDirection"
	case attr.Iface:
		return "interfaceName"
	}
	return ""
}

// names are taken from this list: https://datatracker.ietf.org/doc/html/rfc5102
// To ensure Netflow 9 compatibility, we should restrict to attributes 1-127
func addObiToNetFlowAttrName(name attr.Name, ipv4 bool, dst *netFlowAttributes) error {
	en := attrNameToEntityName(name, ipv4)
	if en == "" {
		return fmt.Errorf("attribute %s not supported in Beyla NetFlow exporter", name)
	}
	elem, err := getElement(en)
	if err != nil {
		return fmt.Errorf("for attribute %s (%d): %w", name, en, err)
	}
	dst.entities = append(dst.entities, elem)
	switch name {
	case attr.Transport:
		dst.setters = append(dst.setters, func(r *ebpf.Record, v entities.InfoElementWithValue) {
			v.SetUnsigned8Value(r.Id.TransportProtocol)
		})
	case attr.SrcAddress:
		if ipv4 {
			dst.setters = append(dst.setters, func(r *ebpf.Record, v entities.InfoElementWithValue) {
				v.SetIPAddressValue(r.Id.SrcIP().IP().To4())
			})
		} else {
			dst.setters = append(dst.setters, func(r *ebpf.Record, v entities.InfoElementWithValue) {
				v.SetIPAddressValue(r.Id.SrcIP().IP().To16())
			})
		}
	case attr.DstAddres:
		if ipv4 {
			dst.setters = append(dst.setters, func(r *ebpf.Record, v entities.InfoElementWithValue) {
				v.SetIPAddressValue(r.Id.DstIP().IP().To4())
			})
		} else {
			dst.setters = append(dst.setters, func(r *ebpf.Record, v entities.InfoElementWithValue) {
				v.SetIPAddressValue(r.Id.DstIP().IP().To16())
			})
		}
	case attr.SrcPort:
		dst.setters = append(dst.setters, func(r *ebpf.Record, v entities.InfoElementWithValue) {
			v.SetUnsigned16Value(r.Id.SrcPort)
		})
	case attr.DstPort:
		dst.setters = append(dst.setters, func(r *ebpf.Record, v entities.InfoElementWithValue) {
			v.SetUnsigned16Value(r.Id.DstPort)
		})
	case attr.IfaceDirection:
		dst.setters = append(dst.setters, func(r *ebpf.Record, v entities.InfoElementWithValue) {
			v.SetUnsigned8Value(r.Metrics.IfaceDirection)
		})
	case attr.Iface:
		dst.setters = append(dst.setters, func(r *ebpf.Record, v entities.InfoElementWithValue) {
			v.SetStringValue(r.Attrs.Interface)
		})
	default:
		return fmt.Errorf("attribute %s not yet supported in Beyla NetFlow exporter", name)
	}

	return nil
}
