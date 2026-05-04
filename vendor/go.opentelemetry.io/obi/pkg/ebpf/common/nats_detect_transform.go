// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

var (
	natsCRLF       = []byte("\r\n")
	natsCmdOK      = []byte("+OK")
	natsCmdErr     = []byte("-ERR")
	natsCmdPing    = []byte("PING")
	natsCmdPong    = []byte("PONG")
	natsCmdInfo    = []byte("INFO")
	natsCmdConnect = []byte("CONNECT")
	natsCmdSub     = []byte("SUB")
	natsCmdUnsub   = []byte("UNSUB")
	natsCmdPub     = []byte("PUB")
	natsCmdMsg     = []byte("MSG")
	natsCmdHPub    = []byte("HPUB")
	natsCmdHMsg    = []byte("HMSG")
)

type NATSInfo struct {
	Operation   string
	Subject     string
	ClientID    string
	PayloadSize int
}

type natsFrame struct {
	info     *NATSInfo
	clientID string
	valid    bool
}

// ProcessPossibleNATSEvent looks for NATS frames in both directions.
// It returns the main span info plus optional extra span info from the peer buffer.
// When only rpkt has span info, the event is reversed and returned as info.
func ProcessPossibleNATSEvent(event *TCPRequestInfo, pkt *largebuf.LargeBuffer, rpkt *largebuf.LargeBuffer) (info *NATSInfo, extraInfo *NATSInfo, ignore bool, err error) {
	reqInfo, reqIgnore, reqErr := ProcessNATSEvent(pkt)
	respInfo, respIgnore, respErr := ProcessNATSEvent(rpkt)

	isPublish := func(info *NATSInfo) bool {
		return info != nil && info.Operation == request.MessagingPublish
	}

	// Both buffers have span-worthy frames (e.g. HPUB + HMSG on same connection).
	if reqErr == nil && !reqIgnore && reqInfo != nil &&
		respErr == nil && !respIgnore && respInfo != nil {
		if isPublish(respInfo) && !isPublish(reqInfo) {
			return respInfo, reqInfo, false, nil
		}

		return reqInfo, respInfo, false, nil
	}

	// Only request buffer has a span.
	if reqErr == nil && !reqIgnore && reqInfo != nil {
		return reqInfo, nil, false, nil
	}

	// Only response buffer has a span -- reverse the event so the
	// connection info reflects the direction of the captured frame.
	if respErr == nil && !respIgnore && respInfo != nil {
		reverseTCPEvent(event)
		return respInfo, nil, false, nil
	}

	// At least one buffer was valid NATS but contained no span-worthy frame.
	if reqErr == nil || respErr == nil {
		return nil, nil, true, nil
	}

	return nil, nil, true, reqErr
}

// ProcessNATSEvent parses a buffer that may contain several NATS frames.
// It returns the first publish or delivered-message frame that can be turned
// into a span, or ignore=true when the buffer is valid NATS traffic but only
// contains non-span control frames.
func ProcessNATSEvent(pkt *largebuf.LargeBuffer) (*NATSInfo, bool, error) {
	if pkt == nil || pkt.Len() == 0 {
		return nil, true, errors.New("packet too short for NATS")
	}

	reader := pkt.NewReader()
	clientID := ""
	for reader.Remaining() > 0 {
		frame, err := parseNATSFrame(&reader)
		if err != nil {
			return nil, true, err
		}
		if frame.clientID != "" {
			clientID = frame.clientID
		}
		if frame.info == nil {
			continue
		}

		frame.info.ClientID = clientID
		return frame.info, false, nil
	}

	return nil, true, nil
}

func parseNATSFrame(reader *largebuf.LargeBufferReader) (natsFrame, error) {
	line, err := readNATSControlLine(reader)
	if err != nil {
		return natsFrame{}, err
	}

	fields := bytes.Fields(line)
	if len(fields) == 0 {
		return natsFrame{}, errors.New("empty NATS command")
	}

	command := fields[0]

	switch {
	case equalFoldASCII(command, natsCmdOK),
		equalFoldASCII(command, natsCmdErr),
		equalFoldASCII(command, natsCmdPing),
		equalFoldASCII(command, natsCmdPong):
		return natsFrame{}, nil
	case equalFoldASCII(command, natsCmdInfo), equalFoldASCII(command, natsCmdConnect):
		return parseNATSInfoOrConnectFrame(command, line)
	case equalFoldASCII(command, natsCmdSub):
		return parseNATSSubFrame(fields)
	case equalFoldASCII(command, natsCmdUnsub):
		return parseNATSUnsubFrame(fields)
	case equalFoldASCII(command, natsCmdPub):
		return parseNATSPUBFrame(reader, fields)
	case equalFoldASCII(command, natsCmdMsg):
		return parseNATSMSGFrame(reader, fields)
	case equalFoldASCII(command, natsCmdHPub):
		return parseNATSHPUBFrame(reader, fields)
	case equalFoldASCII(command, natsCmdHMsg):
		return parseNATSHMSGFrame(reader, fields)
	default:
		return natsFrame{}, errors.New("unsupported NATS command")
	}
}

func parseNATSInfoOrConnectFrame(command, line []byte) (natsFrame, error) {
	rest, err := natsJSONPayload(line, command)
	if err != nil {
		return natsFrame{}, err
	}

	if equalFoldASCII(command, natsCmdInfo) {
		return natsFrame{valid: true}, nil
	}

	var meta struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(rest, &meta); err != nil {
		return natsFrame{}, errors.New("invalid NATS JSON payload")
	}

	return natsFrame{clientID: meta.Name, valid: true}, nil
}

func parseNATSSubFrame(fields [][]byte) (natsFrame, error) {
	if len(fields) != 3 && len(fields) != 4 {
		return natsFrame{}, errors.New("invalid SUB control line")
	}
	if err := validateNATSSID(fields[len(fields)-1]); err != nil {
		return natsFrame{}, err
	}
	return natsFrame{valid: true}, nil
}

func parseNATSUnsubFrame(fields [][]byte) (natsFrame, error) {
	if len(fields) != 2 && len(fields) != 3 {
		return natsFrame{}, errors.New("invalid UNSUB control line")
	}
	if err := validateNATSSID(fields[1]); err != nil {
		return natsFrame{}, err
	}
	if len(fields) == 3 {
		if _, err := parseIntField(fields[2]); err != nil {
			return natsFrame{}, errors.New("invalid UNSUB max_msgs")
		}
	}
	return natsFrame{valid: true}, nil
}

func parseNATSPUBFrame(reader *largebuf.LargeBufferReader, fields [][]byte) (natsFrame, error) {
	subject, size, err := parseNATSPayloadFields(fields)
	if err != nil {
		return natsFrame{}, err
	}
	if err := consumeNATSPayload(reader, size); err != nil {
		return natsFrame{}, err
	}
	return natsFrame{
		info:  &NATSInfo{Operation: request.MessagingPublish, Subject: subject, PayloadSize: size},
		valid: true,
	}, nil
}

func parseNATSMSGFrame(reader *largebuf.LargeBufferReader, fields [][]byte) (natsFrame, error) {
	if len(fields) != 4 && len(fields) != 5 {
		return natsFrame{}, errors.New("invalid MSG control line")
	}
	if err := validateNATSSID(fields[2]); err != nil {
		return natsFrame{}, err
	}
	size, err := parseIntField(fields[len(fields)-1])
	if err != nil {
		return natsFrame{}, errors.New("invalid MSG payload size")
	}
	if err := consumeNATSPayload(reader, size); err != nil {
		return natsFrame{}, err
	}
	return natsFrame{
		info:  &NATSInfo{Operation: request.MessagingProcess, Subject: string(fields[1]), PayloadSize: size},
		valid: true,
	}, nil
}

func parseNATSHPUBFrame(reader *largebuf.LargeBufferReader, fields [][]byte) (natsFrame, error) {
	subject, totalSize, err := parseNATSHeaderPayloadFields(fields)
	if err != nil {
		return natsFrame{}, err
	}
	if err := consumeNATSPayload(reader, totalSize); err != nil {
		return natsFrame{}, err
	}
	return natsFrame{
		info:  &NATSInfo{Operation: request.MessagingPublish, Subject: subject, PayloadSize: totalSize}, // totalSize includes headers + body for HPUB
		valid: true,
	}, nil
}

func parseNATSHMSGFrame(reader *largebuf.LargeBufferReader, fields [][]byte) (natsFrame, error) {
	if len(fields) != 5 && len(fields) != 6 {
		return natsFrame{}, errors.New("invalid HMSG control line")
	}
	if err := validateNATSSID(fields[2]); err != nil {
		return natsFrame{}, err
	}
	hdrSize, err := parseIntField(fields[len(fields)-2])
	if err != nil {
		return natsFrame{}, errors.New("invalid HMSG header size")
	}
	totalSize, err := parseIntField(fields[len(fields)-1])
	if err != nil {
		return natsFrame{}, errors.New("invalid HMSG total size")
	}
	if hdrSize > totalSize {
		return natsFrame{}, errors.New("HMSG header size exceeds total size")
	}
	if err := consumeNATSPayload(reader, totalSize); err != nil {
		return natsFrame{}, err
	}
	return natsFrame{
		info:  &NATSInfo{Operation: request.MessagingProcess, Subject: string(fields[1]), PayloadSize: totalSize}, // totalSize includes headers + body for HMSG
		valid: true,
	}, nil
}

func parseIntField(field []byte) (int, error) {
	if len(field) == 0 {
		return 0, errors.New("invalid integer field")
	}
	return strconv.Atoi(unsafe.String(unsafe.SliceData(field), len(field)))
}

func parseNATSPayloadFields(fields [][]byte) (string, int, error) {
	if len(fields) != 3 && len(fields) != 4 {
		return "", 0, errors.New("invalid NATS payload control line")
	}

	size, err := parseIntField(fields[len(fields)-1])
	if err != nil {
		return "", 0, errors.New("invalid NATS payload size")
	}

	return string(fields[1]), size, nil
}

func parseNATSHeaderPayloadFields(fields [][]byte) (string, int, error) {
	if len(fields) != 4 && len(fields) != 5 {
		return "", 0, errors.New("invalid NATS header payload control line")
	}

	hdrSize, err := parseIntField(fields[len(fields)-2])
	if err != nil {
		return "", 0, errors.New("invalid NATS header size")
	}
	totalSize, err := parseIntField(fields[len(fields)-1])
	if err != nil {
		return "", 0, errors.New("invalid NATS total size")
	}
	if hdrSize > totalSize {
		return "", 0, errors.New("NATS header size exceeds total size")
	}

	return string(fields[1]), totalSize, nil
}

func consumeNATSPayload(reader *largebuf.LargeBufferReader, size int) error {
	if size < 0 {
		return errors.New("negative NATS payload size")
	}

	if err := reader.Skip(size); err != nil {
		return errors.New("truncated NATS payload")
	}

	terminator, err := reader.ReadN(len(natsCRLF))
	if err != nil {
		return errors.New("truncated NATS payload")
	}
	if !bytes.Equal(terminator, natsCRLF) {
		return errors.New("missing NATS payload terminator")
	}

	return nil
}

func readNATSControlLine(reader *largebuf.LargeBufferReader) ([]byte, error) {
	crPos := reader.IndexByte('\r')
	if crPos < 0 {
		return nil, errors.New("missing NATS control line terminator")
	}

	line, err := reader.ReadN(crPos)
	if err != nil {
		return nil, errors.New("missing NATS control line terminator")
	}

	terminator, err := reader.ReadN(len(natsCRLF))
	if err != nil || !bytes.Equal(terminator, natsCRLF) {
		return nil, errors.New("missing NATS control line terminator")
	}

	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return nil, errors.New("empty NATS control line")
	}

	return line, nil
}

func natsJSONPayload(line, command []byte) ([]byte, error) {
	if len(line) <= len(command) {
		return nil, errors.New("missing NATS JSON payload")
	}

	rest := bytes.TrimSpace(line[len(command):])
	if !json.Valid(rest) {
		return nil, errors.New("invalid NATS JSON payload")
	}

	return rest, nil
}

func validateNATSSID(field []byte) error {
	if !isASCIIAlnumBytes(field) {
		return errors.New("invalid NATS sid")
	}
	return nil
}

func TCPToNATSToSpan(trace *TCPRequestInfo, data *NATSInfo) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(&trace.ConnInfo).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	reqType := request.EventTypeNATSClient
	if trace.Direction == directionRecv {
		reqType = request.EventTypeNATSServer
	}

	return request.Span{
		Type:          reqType,
		Method:        data.Operation,
		Path:          data.Subject,
		Statement:     data.ClientID,
		Peer:          peer,
		PeerPort:      int(trace.ConnInfo.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: int64(data.PayloadSize),
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        0,
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(trace.Pid.HostPid),
			UserPID:   app.PID(trace.Pid.UserPid),
			Namespace: trace.Pid.Ns,
		},
	}
}
