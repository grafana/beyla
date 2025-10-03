// Copyright 2020 VMware, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package exporter

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v2"
	"k8s.io/klog/v2"

	"github.com/vmware/go-ipfix/pkg/entities"
)

const startTemplateID uint16 = 255
const defaultCheckConnInterval = 10 * time.Second
const defaultJSONBufferLen = 5000

type templateValue struct {
	elements      []*entities.InfoElement
	minDataRecLen uint16
}

//  1. Tested one exportingProcess process per exporter. Can support multiple collector scenario by
//     creating different instances of exporting process. Need to be tested
//  2. Only one observation point per observation domain is supported,
//     so observation point ID not defined.
//  3. Supports only TCP and UDP; one session at a time. SCTP is not supported.
//  4. UDP needs to send PMTU size packets as per RFC7011. In order to guarantee
//     this, maxMsgSize should be set correctly. maxMsgSize is the maximum
//     payload (IPFIX message) size, not the maximum packet size. If
//     maxMsgSize is not set correctly, the message may be fragmented.
type ExportingProcess struct {
	connToCollector net.Conn
	obsDomainID     uint32
	seqNumber       uint32
	templateID      uint16
	templatesMap    map[uint16]templateValue
	templateMutex   sync.Mutex
	sendJSONRecord  bool
	jsonBufferLen   int
	maxMsgSize      int
	wg              sync.WaitGroup
	isClosed        atomic.Bool
	stopCh          chan struct{}
}

type ExporterTLSClientConfig struct {
	// ServerName is passed to the server for SNI and is used in the client to check server
	// certificates against. If ServerName is empty, the hostname used to contact the
	// server is used.
	ServerName string
	// CAData holds PEM-encoded bytes for trusted root certificates for server.
	CAData []byte
	// CertData holds PEM-encoded bytes.
	CertData []byte
	// KeyData holds PEM-encoded bytes.
	KeyData []byte
	// List of supported cipher suites.
	// From https://pkg.go.dev/crypto/tls#pkg-constants
	// The order of the list is ignored.Note that TLS 1.3 ciphersuites are not configurable.
	// For DTLS, cipher suites are from https://pkg.go.dev/github.com/pion/dtls/v2@v2.2.12/internal/ciphersuite#ID.
	CipherSuites []uint16
	// Min TLS version.
	// From https://pkg.go.dev/crypto/tls#pkg-constants
	// Not configurable for DTLS, as only DTLS 1.2 is supported.
	MinVersion uint16
}

type ExporterInput struct {
	// CollectorAddress needs to be provided in hostIP:port format.
	CollectorAddress string
	// CollectorProtocol needs to be provided in lower case format.
	// We support "tcp" and "udp" protocols.
	CollectorProtocol   string
	ObservationDomainID uint32
	TempRefTimeout      uint32
	// TLSClientConfig is set to use an encrypted connection to the collector.
	TLSClientConfig *ExporterTLSClientConfig
	IsIPv6          bool
	SendJSONRecord  bool
	// JSONBufferLen is recommended for sending json records. If not given a
	// valid value, we use a default of 5000B
	JSONBufferLen int
	// MaxMsgSize can be used to provide a custom maximum IPFIX message
	// size. If it is omitted, we will use an appropriate default based on
	// the configured protocol. For UDP, we want to avoid fragmentation, so
	// the MaxMsgSize should be set by taking into account the PMTU and
	// header sizes. The recommended approach is to keep MaxMsgSize unset
	// and provide the correct PMTU value.
	MaxMsgSize int
	// PathMTU is used to calculate the maximum message size when the
	// protocol is UDP. It is ignored for TCP. If both MaxMsgSize and
	// PathMTU are set, and MaxMsgSize is incompatible with the provided
	// PathMTU, exporter initialization will fail.
	PathMTU           int
	CheckConnInterval time.Duration
}

func calculateMaxMsgSize(proto string, requestedSize int, pathMTU int, isIPv6 bool) (int, error) {
	if requestedSize > 0 && (requestedSize < entities.MinSupportedMsgSize || requestedSize > entities.MaxSocketMsgSize) {
		return 0, fmt.Errorf("requested message size should be between %d and %d", entities.MinSupportedMsgSize, entities.MaxSocketMsgSize)
	}
	if proto == "tcp" {
		if requestedSize == 0 {
			return entities.MaxSocketMsgSize, nil
		} else {
			return requestedSize, nil
		}
	}
	// UDP protocol
	if pathMTU == 0 {
		if requestedSize == 0 {
			klog.InfoS("Neither max IPFIX message size nor PMTU were provided, defaulting to min message size", "messageSize", entities.MinSupportedMsgSize)
			return entities.MinSupportedMsgSize, nil
		}
		klog.InfoS("PMTU was not provided, configured message size may cause fragmentation", "messageSize", requestedSize)
		return requestedSize, nil
	}
	// 20-byte IPv4, 8-byte UDP header
	mtuDeduction := 28
	if isIPv6 {
		// An extra 20 bytes for IPv6
		mtuDeduction += 20
	}
	maxMsgSize := pathMTU - mtuDeduction
	if maxMsgSize < entities.MinSupportedMsgSize {
		return 0, fmt.Errorf("provided PMTU %d is not large enough to accommodate min message size %d", pathMTU, entities.MinSupportedMsgSize)
	}
	if requestedSize > maxMsgSize {
		return 0, fmt.Errorf("requested message size %d exceeds max message size %d calculated from provided PMTU", requestedSize, maxMsgSize)
	}
	if requestedSize > 0 {
		return requestedSize, nil
	}
	return maxMsgSize, nil
}

// InitExportingProcess takes in collector address(net.Addr format), obsID(observation ID)
// and tempRefTimeout(template refresh timeout). tempRefTimeout is applicable only
// for collectors listening over UDP; unit is seconds. For TCP, you can pass any
// value and it will be ignored. For UDP, if 0 is passed, 600s is used as the default.
func InitExportingProcess(input ExporterInput) (*ExportingProcess, error) {
	if input.CollectorProtocol != "tcp" && input.CollectorProtocol != "udp" {
		return nil, fmt.Errorf("unsupported collector protocol: %s", input.CollectorProtocol)
	}
	var conn net.Conn
	var err error
	if input.TLSClientConfig != nil {
		tlsConfig := input.TLSClientConfig
		switch input.CollectorProtocol {
		case "tcp": // use TLS
			config, configErr := createClientConfig(tlsConfig)
			if configErr != nil {
				return nil, configErr
			}
			conn, err = tls.Dial(input.CollectorProtocol, input.CollectorAddress, config)
			if err != nil {
				return nil, fmt.Errorf("cannot create the TLS connection to the Collector %q: %w", input.CollectorAddress, err)
			}
		case "udp": // use DTLS
			// TODO: support client authentication
			if len(tlsConfig.CertData) > 0 || len(tlsConfig.KeyData) > 0 {
				return nil, fmt.Errorf("client-authentication is not supported yet for DTLS")
			}
			if tlsConfig.MinVersion != 0 && tlsConfig.MinVersion != tls.VersionTLS12 {
				return nil, fmt.Errorf("DTLS 1.2 is the only supported version")
			}
			roots := x509.NewCertPool()
			ok := roots.AppendCertsFromPEM(tlsConfig.CAData)
			if !ok {
				return nil, fmt.Errorf("failed to parse root certificate")
			}
			// If tlsConfig.CipherSuites is nil, cipherSuites should also be nil!
			var cipherSuites []dtls.CipherSuiteID
			for _, cipherSuite := range tlsConfig.CipherSuites {
				cipherSuites = append(cipherSuites, dtls.CipherSuiteID(cipherSuite))
			}
			config := &dtls.Config{
				RootCAs:              roots,
				ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
				ServerName:           tlsConfig.ServerName,
				CipherSuites:         cipherSuites,
			}
			udpAddr, err := net.ResolveUDPAddr(input.CollectorProtocol, input.CollectorAddress)
			if err != nil {
				return nil, err
			}
			conn, err = dtls.Dial(udpAddr.Network(), udpAddr, config)
			if err != nil {
				return nil, fmt.Errorf("cannot create the DTLS connection to the Collector %q: %w", udpAddr.String(), err)
			}
		}
	} else {
		conn, err = net.Dial(input.CollectorProtocol, input.CollectorAddress)
		if err != nil {
			return nil, fmt.Errorf("cannot create the connection to the Collector %q: %w", input.CollectorAddress, err)
		}
	}
	var isIPv6 bool
	switch addr := conn.RemoteAddr().(type) {
	case *net.TCPAddr:
		isIPv6 = addr.IP.To4() == nil
	case *net.UDPAddr:
		isIPv6 = addr.IP.To4() == nil
	default:
		return nil, fmt.Errorf("unsupported net.Addr type %T", addr)
	}
	expProc := &ExportingProcess{
		connToCollector: conn,
		obsDomainID:     input.ObservationDomainID,
		seqNumber:       0,
		templateID:      startTemplateID,
		templatesMap:    make(map[uint16]templateValue),
		sendJSONRecord:  input.SendJSONRecord,
		wg:              sync.WaitGroup{},
		stopCh:          make(chan struct{}),
	}

	if expProc.sendJSONRecord {
		if input.JSONBufferLen <= 0 {
			expProc.jsonBufferLen = defaultJSONBufferLen
		} else {
			expProc.jsonBufferLen = input.JSONBufferLen
		}
	} else {
		maxMsgSize, err := calculateMaxMsgSize(input.CollectorProtocol, input.MaxMsgSize, input.PathMTU, isIPv6)
		if err != nil {
			return nil, err
		}
		klog.InfoS("Calculated max IPFIX message size", "size", maxMsgSize)
		expProc.maxMsgSize = maxMsgSize
	}

	// Start a goroutine to check whether the collector has already closed the TCP connection.
	if input.CollectorProtocol == "tcp" {
		interval := input.CheckConnInterval
		if interval == 0 {
			interval = defaultCheckConnInterval
		}
		expProc.wg.Add(1)
		go func() {
			defer expProc.wg.Done()
			ticker := time.NewTicker(interval)
			oneByteForRead := make([]byte, 1)
			defer ticker.Stop()
			for {
				select {
				case <-expProc.stopCh:
					return
				case <-ticker.C:
					isConnected := expProc.checkConnToCollector(oneByteForRead)
					if !isConnected {
						klog.Error("Connector has closed its side of the TCP connection, closing our side")
						expProc.closeConnToCollector()
						return
					}
				}
			}
		}()
	}

	// Template refresh logic is only for UDP transport.
	if input.CollectorProtocol == "udp" {
		if input.TempRefTimeout == 0 {
			// Default value
			input.TempRefTimeout = entities.TemplateRefreshTimeOut
		}
		expProc.wg.Add(1)
		go func() {
			defer expProc.wg.Done()
			ticker := time.NewTicker(time.Duration(input.TempRefTimeout) * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-expProc.stopCh:
					return
				case <-ticker.C:
					klog.V(2).Info("Sending refreshed templates to the collector")
					err := expProc.sendRefreshedTemplates()
					if err != nil {
						klog.Errorf("Error when sending refreshed templates: %v", err)
					} else {
						klog.V(2).Info("Sent refreshed templates to the collector")
					}
				}
			}
		}()
	}
	return expProc, nil
}

func (ep *ExportingProcess) sendSet(set entities.Set, doDataRecSanityCheck bool, buf *bytes.Buffer) (int, error) {
	// Iterate over all records in the set.
	setType := set.GetSetType()
	if setType == entities.Undefined {
		return 0, fmt.Errorf("set type is not properly defined")
	}
	if setType == entities.Template {
		for _, record := range set.GetRecords() {
			ep.updateTemplate(record.GetTemplateID(), record.GetOrderedElementList(), record.GetMinDataRecordLen())
		}
	} else if setType == entities.Data && doDataRecSanityCheck {
		for _, record := range set.GetRecords() {
			if err := ep.dataRecSanityCheck(record); err != nil {
				return 0, fmt.Errorf("error when doing sanity check:%v", err)
			}
		}
	}
	// Update the length in set header before sending the message.
	set.UpdateLenInHeader()

	var bytesSent int
	var err error
	if ep.sendJSONRecord {
		if setType == entities.Data {
			_, bytesSent, err = ep.createAndSendJSONRecords(set.GetRecords(), buf)
		}
	} else {
		bytesSent, err = ep.createAndSendIPFIXMsg(set, buf)
	}
	return bytesSent, err
}

// SendSet sends the provided set and returns the number of bytes written and an error if applicable.
func (ep *ExportingProcess) SendSet(set entities.Set) (int, error) {
	return ep.sendSet(set, true, &bytes.Buffer{})
}

// SendDataRecords is a specialized version of SendSet which can send a list of data records more
// efficiently. All the data records must be for the same template ID. This function performs fewer
// sanity checks on the data records, compared to SendSet. This function can also take a reusable
// buffer as a parameter to avoid repeated memory allocations. You can use nil as the buffer if you
// want this function to be responsible for allocation. SendDataRecords returns the number of
// records successfully sent, the total number of bytes sent, and an error if applicable.
func (ep *ExportingProcess) SendDataRecords(templateID uint16, records []entities.Record, buf *bytes.Buffer) (int, int, error) {
	if buf == nil {
		if ep.sendJSONRecord {
			buf = bytes.NewBuffer(make([]byte, 0, ep.jsonBufferLen))
		} else {
			buf = bytes.NewBuffer(make([]byte, 0, ep.maxMsgSize))
		}
	} else {
		buf.Reset()
	}

	if ep.sendJSONRecord {
		return ep.createAndSendJSONRecords(records, buf)
	}

	recordsSent := 0
	bytesSent := 0

	set := entities.NewSet(false)

	for recordsSent < len(records) {
		// length will always match set.GetSetLength
		length := entities.MsgHeaderLength + entities.SetHeaderLen
		if err := set.PrepareSet(entities.Data, templateID); err != nil {
			return 0, 0, err
		}
		numRecordsInSet := 0
		for idx := recordsSent; idx < len(records); idx++ {
			record := records[idx]
			recordLength := record.GetRecordLength()
			// If the record fits in the current message, add it to the set and continue to the next record.
			if length+recordLength <= ep.maxMsgSize {
				if err := set.AddRecordV3(record); err != nil {
					return recordsSent, bytesSent, fmt.Errorf("error when adding record to data set: %w", err)
				}
				numRecordsInSet += 1
				length += recordLength
				continue
			}
			// There is no record in the set currently, yet this new record cannot fit!
			if numRecordsInSet == 0 {
				return recordsSent, bytesSent, fmt.Errorf("record exceeds max size")
			}
			// Break out of the loop and send the set
			break
		}
		// Time to send the set / message. Note that it is guaranteed that numRecordsInSet > 1.
		// We choose not to invoke dataRecSanityCheck on the individual records.
		n, err := ep.sendSet(set, false, buf)
		bytesSent += n
		if err != nil {
			return recordsSent, bytesSent, fmt.Errorf("error when sending data set: %w", err)
		}
		recordsSent += numRecordsInSet
		// We have more records to send, so prepare shared data structures.
		if recordsSent < len(records) {
			set.ResetSet()
			buf.Reset()
		}
	}

	return recordsSent, bytesSent, nil
}

// GetMsgSizeLimit returns the maximum IPFIX message size that this exporter is allowed to write to
// the connection. If the exporter is configured to send marshalled JSON records instead, this
// function will return 0.
func (ep *ExportingProcess) GetMsgSizeLimit() int {
	return ep.maxMsgSize
}

// CloseConnToCollector closes the connection to the collector.
// It can safely be closed more than once, and subsequent calls will be no-ops.
func (ep *ExportingProcess) CloseConnToCollector() {
	ep.closeConnToCollector()
	ep.wg.Wait()
}

// closeConnToCollector is the internal version of CloseConnToCollector. It closes all the resources
// but does not wait for the ep.wg counter to get to 0. Goroutines which need to terminate in order
// for ep.wg to be decremented can safely call closeConnToCollector.
func (ep *ExportingProcess) closeConnToCollector() {
	if ep.isClosed.Swap(true) {
		return
	}
	klog.Info("Closing connection to the collector")
	close(ep.stopCh)
	if err := ep.connToCollector.Close(); err != nil {
		// Just log the error that happened when closing the connection. Not returning error
		// as we do not expect library consumers to exit their programs with this error.
		klog.Errorf("Error when closing connection to the collector: %v", err)
	}
}

// checkConnToCollector checks whether the connection from exporter is still open
// by trying to read from connection. Closed connection will return EOF from read.
func (ep *ExportingProcess) checkConnToCollector(oneByteForRead []byte) bool {
	ep.connToCollector.SetReadDeadline(time.Now().Add(time.Millisecond))
	if _, err := ep.connToCollector.Read(oneByteForRead); err == io.EOF {
		return false
	}
	return true
}

// NewTemplateID is called to get ID when creating new template record.
func (ep *ExportingProcess) NewTemplateID() uint16 {
	ep.templateID++
	return ep.templateID
}

// createAndSendIPFIXMsg takes in a set as input, creates the IPFIX message, and sends it out.
// TODO: This method will change when we support sending multiple sets.
func (ep *ExportingProcess) createAndSendIPFIXMsg(set entities.Set, buf *bytes.Buffer) (int, error) {
	n, err := WriteIPFIXMsgToBuffer(set, ep.obsDomainID, ep.seqNumber, time.Now(), buf)
	if err != nil {
		return 0, err
	}
	if n > ep.maxMsgSize {
		return 0, fmt.Errorf("IPFIX message length %d exceeds maximum size of %d", n, ep.maxMsgSize)
	}

	// Send the message on the exporter connection.
	bytesSent, err := ep.connToCollector.Write(buf.Bytes())

	if err != nil {
		return bytesSent, fmt.Errorf("error when sending message on the connection: %v", err)
	} else if bytesSent != n {
		return bytesSent, fmt.Errorf("could not send the complete message on the connection")
	}

	if set.GetSetType() == entities.Data {
		ep.seqNumber = ep.seqNumber + set.GetNumberOfRecords()
	}

	return bytesSent, nil
}

// createAndSendJSONRecords takes in a slice of records as input, marshals each record to JSON using
// the provided buffer, and writes it to the connection. It returns the number of records sent, the
// total number of bytes sent, and an error if applicable.
func (ep *ExportingProcess) createAndSendJSONRecords(records []entities.Record, buf *bytes.Buffer) (int, int, error) {
	buf.Grow(ep.jsonBufferLen)
	recordsSent := 0
	bytesSent := 0
	elements := make(map[string]interface{})
	message := make(map[string]interface{}, 2)
	for _, record := range records {
		clear(elements)
		orderedElements := record.GetOrderedElementList()
		for _, element := range orderedElements {
			switch element.GetDataType() {
			case entities.Unsigned8:
				elements[element.GetName()] = element.GetUnsigned8Value()
			case entities.Unsigned16:
				elements[element.GetName()] = element.GetUnsigned16Value()
			case entities.Unsigned32:
				elements[element.GetName()] = element.GetUnsigned32Value()
			case entities.Unsigned64:
				elements[element.GetName()] = element.GetUnsigned64Value()
			case entities.Signed8:
				elements[element.GetName()] = element.GetSigned8Value()
			case entities.Signed16:
				elements[element.GetName()] = element.GetSigned16Value()
			case entities.Signed32:
				elements[element.GetName()] = element.GetSigned32Value()
			case entities.Signed64:
				elements[element.GetName()] = element.GetSigned64Value()
			case entities.Float32:
				elements[element.GetName()] = element.GetFloat32Value()
			case entities.Float64:
				elements[element.GetName()] = element.GetFloat64Value()
			case entities.Boolean:
				elements[element.GetName()] = element.GetBooleanValue()
			case entities.DateTimeSeconds:
				elements[element.GetName()] = element.GetUnsigned32Value()
			case entities.DateTimeMilliseconds:
				elements[element.GetName()] = element.GetUnsigned64Value()
			case entities.DateTimeMicroseconds, entities.DateTimeNanoseconds:
				return recordsSent, bytesSent, fmt.Errorf("API does not support micro and nano seconds types yet")
			case entities.MacAddress:
				elements[element.GetName()] = element.GetMacAddressValue()
			case entities.Ipv4Address, entities.Ipv6Address:
				elements[element.GetName()] = element.GetIPAddressValue()
			case entities.String:
				elements[element.GetName()] = element.GetStringValue()
			default:
				return recordsSent, bytesSent, fmt.Errorf("API supports only valid information elements with datatypes given in RFC7011")
			}
		}
		message["ipfix"] = elements
		message["@timestamp"] = time.Now().Format(time.RFC3339)
		encoder := json.NewEncoder(buf)
		if err := encoder.Encode(message); err != nil {
			return recordsSent, bytesSent, fmt.Errorf("error when encoding message to JSON: %v", err)
		}
		// Send the message on the exporter connection.
		bytes, err := ep.connToCollector.Write(buf.Bytes())
		bytesSent += bytes
		if err != nil {
			return recordsSent, bytesSent, fmt.Errorf("error when sending message on the connection: %v", err)
		}
		recordsSent += 1
		buf.Reset()
	}
	return recordsSent, bytesSent, nil
}

func (ep *ExportingProcess) updateTemplate(id uint16, elements []entities.InfoElementWithValue, minDataRecLen uint16) {
	ep.templateMutex.Lock()
	defer ep.templateMutex.Unlock()

	if _, exist := ep.templatesMap[id]; exist {
		return
	}
	ep.templatesMap[id] = templateValue{
		make([]*entities.InfoElement, len(elements)),
		minDataRecLen,
	}
	for i, elem := range elements {
		ep.templatesMap[id].elements[i] = elem.GetInfoElement()
	}
}

//nolint:unused // Keeping this function for reference.
func (ep *ExportingProcess) deleteTemplate(id uint16) error {
	ep.templateMutex.Lock()
	defer ep.templateMutex.Unlock()

	if _, exist := ep.templatesMap[id]; !exist {
		return fmt.Errorf("template %d does not exist in exporting process", id)
	}
	delete(ep.templatesMap, id)
	return nil
}

func (ep *ExportingProcess) sendRefreshedTemplates() error {
	// Send refreshed template for every template in template map
	templateSets := make([]entities.Set, 0)

	ep.templateMutex.Lock()
	for templateID, tempValue := range ep.templatesMap {
		tempSet, err := entities.MakeTemplateSet(templateID, tempValue.elements)
		if err != nil {
			return err
		}
		templateSets = append(templateSets, tempSet)
	}
	ep.templateMutex.Unlock()

	for _, templateSet := range templateSets {
		if _, err := ep.SendSet(templateSet); err != nil {
			return err
		}
	}
	return nil
}

func (ep *ExportingProcess) dataRecSanityCheck(rec entities.Record) error {
	templateID := rec.GetTemplateID()

	ep.templateMutex.Lock()
	defer ep.templateMutex.Unlock()

	if _, exist := ep.templatesMap[templateID]; !exist {
		return fmt.Errorf("process: templateID %d does not exist in exporting process", templateID)
	}
	if rec.GetFieldCount() != uint16(len(ep.templatesMap[templateID].elements)) {
		return fmt.Errorf("process: field count of data does not match templateID %d", templateID)
	}

	if rec.GetRecordLength() < int(ep.templatesMap[templateID].minDataRecLen) {
		return fmt.Errorf("process: Data Record does not pass the min required length (%d) check for template ID %d", ep.templatesMap[templateID].minDataRecLen, templateID)
	}
	return nil
}

func createClientConfig(config *ExporterTLSClientConfig) (*tls.Config, error) {
	tlsMinVersion := config.MinVersion
	// This should already be the default value for tls.Config, but we duplicate the earlier
	// implementation, which was explicitly setting it to 1.2.
	if tlsMinVersion == 0 {
		tlsMinVersion = tls.VersionTLS12
	}
	// #nosec G402: client is in charge of setting the min TLS version. We use 1.2 as the
	// default, which is secure.
	tlsConfig := &tls.Config{
		ServerName:   config.ServerName,
		CipherSuites: config.CipherSuites,
		MinVersion:   tlsMinVersion,
	}
	// Use system roots if config.CAData == nil.
	if config.CAData != nil {
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM(config.CAData)
		if !ok {
			return nil, fmt.Errorf("failed to parse root certificate")
		}
		tlsConfig.RootCAs = roots
	}
	// Don't use a client certificate if config.CertData == nil.
	if config.CertData != nil {
		cert, err := tls.X509KeyPair(config.CertData, config.KeyData)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return tlsConfig, nil
}
