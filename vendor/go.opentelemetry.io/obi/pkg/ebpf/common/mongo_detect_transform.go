// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"unsafe"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"go.mongodb.org/mongo-driver/v2/bson"

	trace2 "go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

type mongoSpanInfo struct {
	OpName        string
	Collection    string
	DB            string
	Success       bool
	Error         string
	ErrorCode     int
	ErrorCodeName string
}

// https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#standard-message-header
type msgHeader struct {
	MessageLength int32
	RequestID     int32
	ResponseTo    int32
	OpCode        int32
}

// https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#sections
type SectionType uint8

const (
	sectionTypeBody SectionType = iota
	sectionTypeDocumentSequence
)

type mongoSection struct {
	Type SectionType
	Body bson.D // in case of sectionTypeBody, this will contain the BSON document
}

const (
	msgHeaderSize = 16
	int32Size     = 4
	// Flags https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#flag-bits

	flagCheckSumPreset = 0x1 // indicates that the checksum is present
	flagMoreToCome     = 0x2 // indicates that there are more sections to come in the message
	allowedFlags       = flagCheckSumPreset | flagMoreToCome
	flagExhaustAllowed = 0x10000 // indicates that the request is allowed to be sent with moreToCome set

	// OpCodes https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#opcodes
	opMsg = 2013
	// TODO (mongo) support compressed messages (OP_COMPRESSED)
	// TODO (mongo) support legacy messages (OP_QUERY, OP_GET_MORE, OP_INSERT, OP_UPDATE, OP_DELETE, OP_REPLY)

	commHello             = "hello"
	commIsMaster          = "isMaster"
	commPing              = "ping"
	commIsWritablePrimary = "isWritablePrimary"
	commAtlasVersion      = "atlasVersion"

	commInsert = "insert"
	commUpdate = "update"
	commFind   = "find"
	commDelete = "delete"

	commFindAndModify = "findAndModify"
	commAggregate     = "aggregate"
	commCount         = "count"
	commDistinct      = "distinct"
	commMapReduce     = "mapReduce"
)

type MongoRequestKey struct {
	connInfo  BpfConnectionInfoT
	requestID int32
}

type MongoRequestValue struct {
	RequestSections  []mongoSection
	ResponseSections []mongoSection
	StartTime        int64 // timestamp when the request was received
	EndTime          int64 // timestamp when the response was received
	Flags            int32 // Flags to indicate the state of the request
}

func (m *MongoRequestValue) inRequest() bool {
	return len(m.ResponseSections) == 0
}

type PendingMongoDBRequests = *expirable.LRU[MongoRequestKey, *MongoRequestValue]

func makeRequestKey(isResponse bool, header *msgHeader, connInfo BpfConnectionInfoT) MongoRequestKey {
	if isResponse {
		return MongoRequestKey{
			connInfo:  connInfo,
			requestID: header.ResponseTo,
		}
	} else {
		return MongoRequestKey{
			connInfo:  connInfo,
			requestID: header.RequestID,
		}
	}
}

func requestTime(isResponse bool, startTime int64, endTime int64) int64 {
	if isResponse {
		return endTime
	}
	return startTime
}

func ProcessMongoEvent(buf []uint8, startTime int64, endTime int64, connInfo BpfConnectionInfoT, requests PendingMongoDBRequests) (*MongoRequestValue, bool, error) {
	if len(buf) < msgHeaderSize {
		return nil, false, errors.New("packet too short for MongoDB header")
	}

	header, err := parseMongoHeader(buf)
	if err != nil {
		return nil, false, err
	}

	isResponse := header.ResponseTo != 0
	var pendingRequest *MongoRequestValue
	var moreToCome bool
	time := requestTime(isResponse, startTime, endTime)
	key := makeRequestKey(isResponse, header, connInfo)
	inFlightRequest, ok := requests.Get(key)
	if !ok && isResponse {
		return nil, false, fmt.Errorf("no in-flight MongoDB request found for key %d", header.ResponseTo)
	}
	if isResponse && len(buf) == msgHeaderSize {
		// TODO (mongo) currently the response is only the header, since the client sends only the first 16 bytes at first,
		// we need to fix the tcp path to send the response body as well
		// for now we just dont add response section
		requests.Remove(key)
		// If this is a response and there are no more sections to come, we can finalize the request
		return inFlightRequest, false, nil
	}
	pendingRequest, moreToCome, err = parseMongoMessage(buf, *header, time, isResponse, inFlightRequest)
	if err != nil {
		return nil, false, fmt.Errorf("failed to parse MongoDB response: %w", err)
	}
	if pendingRequest == nil {
		return nil, false, errors.New("no MongoDB request or response found in the message")
	}
	if !moreToCome && isResponse {
		// If this is a response and there are no more sections to come, we can finalize the request
		return pendingRequest, false, nil
	}
	requests.Add(key, pendingRequest)
	return nil, true, nil
}

func parseMongoMessage(buf []uint8, hdr msgHeader, time int64, isResponse bool, pendingRequest *MongoRequestValue) (*MongoRequestValue, bool, error) {
	switch hdr.OpCode {
	case opMsg:
		return parseOpMessage(buf, time, isResponse, pendingRequest)
	default:
		return nil, false, fmt.Errorf("unsupported MongoDB operation code %d", hdr.OpCode)
	}
}

func validateOpMsg(isResponse bool, flagBits int32, pendingRequest *MongoRequestValue) (bool, error) {
	// TODO (mongo): maybe add checksum validation to avoid false positives? (only if we have the full packet)
	moreToCome := flagBits&flagMoreToCome != 0
	if isResponse {
		exhaustAllowed := pendingRequest.Flags&flagExhaustAllowed != 0
		if moreToCome && !exhaustAllowed {
			return false, errors.New("MongoDB response with moreToCome flag set but exhaustAllowed is not set")
		}
		if pendingRequest.inRequest() && pendingRequest.Flags&flagMoreToCome != 0 {
			return false, errors.New("MongoDB request expects more sections but response is sent")
		}
	} else {
		switch {
		case pendingRequest == nil:
			return true, nil
		case !pendingRequest.inRequest():
			return false, errors.New("MongoDB request received already started receiving response")
		case pendingRequest.Flags&flagMoreToCome == 0:
			return false, errors.New("MongoDB request with moreToCome flag not set but got another request")
		}
	}
	return moreToCome, nil
}

func addSectionToMessage(isResponse bool, pendingRequest *MongoRequestValue, sections []mongoSection, flagBits int32, time int64) (*MongoRequestValue, error) {
	if isResponse {
		if pendingRequest == nil {
			return nil, errors.New("MongoDB response received but no pending request found")
		}
		pendingRequest.ResponseSections = append(pendingRequest.ResponseSections, sections...)
		pendingRequest.Flags = flagBits
		if pendingRequest.EndTime < time {
			pendingRequest.EndTime = time
		}
	} else {
		if pendingRequest == nil {
			pendingRequest = &MongoRequestValue{
				RequestSections: sections,
				StartTime:       time,
				Flags:           flagBits,
			}
		} else {
			pendingRequest.RequestSections = append(pendingRequest.RequestSections, sections...)
			pendingRequest.Flags = flagBits
			if pendingRequest.StartTime > time {
				pendingRequest.StartTime = time
			}
		}
	}
	return pendingRequest, nil
}

// MONGODB_OP_MSG packet structure:
// +------------+-------------+------------------+
// | header      | flagBits    | sections  | checksum |
// +------------+-------------+------------------+
// |    16B      |     4B      |     ?     | optional 4B |
// +------------+-------------+------------------+
func parseOpMessage(buf []uint8, time int64, isResponse bool, pendingRequest *MongoRequestValue) (*MongoRequestValue, bool, error) {
	flagBits := int32(binary.LittleEndian.Uint32(buf[msgHeaderSize : msgHeaderSize+int32Size]))
	err := validateFlagBits(flagBits)
	if err != nil {
		return nil, false, err
	}

	moreToCome, err := validateOpMsg(isResponse, flagBits, pendingRequest)
	if err != nil {
		return nil, false, err
	}
	sections, err := parseSections(buf[msgHeaderSize+int32Size:])
	if err != nil {
		return nil, false, fmt.Errorf("failed to parse MongoDB sections: %w", err)
	}
	if len(sections) == 0 {
		return nil, false, errors.New("no MongoDB sections found in the message")
	}
	pendingRequest, err = addSectionToMessage(isResponse, pendingRequest, sections, flagBits, time)
	if err != nil {
		return nil, false, err
	}
	return pendingRequest, moreToCome, nil
}

func parseSections(buf []uint8) ([]mongoSection, error) {
	offSet := 0
	sections := []mongoSection{}
	for offSet < len(buf) {

		if len(buf[offSet:]) < int32Size {
			return nil, errors.New("not enough data for section header")
		}

		sectionType := SectionType(buf[offSet])
		offSet++

		switch sectionType {
		// https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#kind-0--body
		case sectionTypeBody:
			doc, bodyLength := parseBodySection(buf[offSet:])
			sections = append(sections, mongoSection{
				Type: sectionType,
				Body: doc,
			})
			offSet += bodyLength
		// https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/#kind-1--document-sequence
		case sectionTypeDocumentSequence:
			sections = append(sections, mongoSection{
				Type: sectionTypeDocumentSequence,
			})
			length := int(binary.LittleEndian.Uint32(buf[offSet : offSet+int32Size]))
			offSet += length
			// TODO (mongo) actually read documents? for now we just skip them
		default:
			return nil, errors.New("unsupported MongoDB section type: " + string(sectionType))
		}
	}
	if len(sections) == 0 {
		return nil, errors.New("no MongoDB sections found in the message")
	}
	return sections, nil
}

func parseBodySection(buf []byte) (bson.D, int) {
	if len(buf) < int32Size {
		return bson.D{}, len(buf)
	}
	bodyLength := int(binary.LittleEndian.Uint32(buf[:int32Size]))

	if len(buf) < bodyLength {
		return bson.D{}, len(buf)
	}

	bodyData := buf[:bodyLength]
	// TODO (mongo) we need to parse partial bson parsing, we won't always get the full tcp payload, so we want to extract as many fields as we can
	var doc bson.D
	err := bson.Unmarshal(bodyData, &doc)
	if err != nil {
		return bson.D{}, bodyLength
	}
	return doc, bodyLength
}

func parseMongoHeader(pkt []byte) (*msgHeader, error) {
	header := &msgHeader{
		MessageLength: int32(binary.LittleEndian.Uint32(pkt[0:int32Size])),
		RequestID:     int32(binary.LittleEndian.Uint32(pkt[int32Size : 2*int32Size])),
		ResponseTo:    int32(binary.LittleEndian.Uint32(pkt[2*int32Size : 3*int32Size])),
		OpCode:        int32(binary.LittleEndian.Uint32(pkt[3*int32Size : 4*int32Size])),
	}
	err := validateMsgHeader(header)
	if err != nil {
		return nil, err
	}
	return header, nil
}

func validateMsgHeader(header *msgHeader) error {
	if header.MessageLength < msgHeaderSize {
		return errors.New("invalid MongoDB message length")
	}
	if header.RequestID < 0 {
		return errors.New("invalid MongoDB request ID")
	}
	if header.ResponseTo < 0 {
		return errors.New("invalid MongoDB response ID")
	}
	return nil
}

/*
The first 16 bits (0-15) are required and parsers MUST Error if an unknown bit is set.
*/
func validateFlagBits(flagBits int32) error {
	if uint16(flagBits&0xFFFF)&^allowedFlags != 0 {
		return fmt.Errorf("invalid MongoDB flag bits: %d, allowed bits are: %d", flagBits, allowedFlags)
	}
	return nil
}

func mongoInfoFromEvent(event *TCPRequestInfo, requestBuffer []byte, responseBuffer []byte, mongoRequestCache PendingMongoDBRequests) *mongoSpanInfo {
	if event.Direction == 0 {
		return nil
	}
	var mongoRequest *MongoRequestValue
	var moreToCome bool
	_, _, err := ProcessMongoEvent(requestBuffer, int64(event.StartMonotimeNs), int64(event.EndMonotimeNs), event.ConnInfo, mongoRequestCache)
	if err != nil {
		return nil
	}
	mongoRequest, moreToCome, err = ProcessMongoEvent(responseBuffer, int64(event.StartMonotimeNs), int64(event.EndMonotimeNs), event.ConnInfo, mongoRequestCache)
	if err != nil || mongoRequest == nil || moreToCome {
		return nil
	}
	mongoInfo, err := getMongoInfo(mongoRequest)
	if err == nil {
		return mongoInfo
	}
	return nil
}

func getMongoInfo(request *MongoRequestValue) (*mongoSpanInfo, error) {
	spanInfo := &mongoSpanInfo{}
	if request == nil || len(request.RequestSections) == 0 {
		return nil, errors.New("no MongoDB request sections found")
	}

	// For simplicity, we assume the first section is the main one.
	// In a real-world scenario, you might want to handle multiple sections.
	requestSection := request.RequestSections[0]
	if requestSection.Type != sectionTypeBody {
		return nil, errors.New("first MongoDB section is not of type body")
	}
	if len(requestSection.Body) == 0 {
		// couldn't parse mongodb section, assume operation is *
		spanInfo.OpName = "*"
	} else {
		// first element in the request body is the operation name
		op, collection, err := parseFirstField(requestSection.Body[0])
		if err != nil {
			return nil, err
		}
		spanInfo.OpName = op
		spanInfo.Collection = collection
		db, ok := findStringInBson(requestSection.Body, "$db")
		if ok {
			spanInfo.DB = db
		}
	}

	if len(request.ResponseSections) == 0 {
		// TODO (mongo) no response sections, we assume the operation was successful, even tho this is bad
		spanInfo.Success = true
	} else {
		responseSection := request.ResponseSections[0]
		if len(responseSection.Body) == 0 {
			return nil, errors.New("no MongoDB body found in the response section")
		}
		success, ok := findDoubleInBson(responseSection.Body, "ok")
		if !ok {
			return nil, errors.New("no 'ok' field found in MongoDB response")
		}
		spanInfo.Success = success == float64(1)
		if spanInfo.Success {
			// If the operation was successful, we can skip Error handling.
			return spanInfo, nil
		}
		errorMsg, ok := findStringInBson(responseSection.Body, "errmsg")
		if ok {
			spanInfo.Error = errorMsg
		}
		errorCode, ok := findIntInBson(responseSection.Body, "code")
		if ok {
			spanInfo.ErrorCode = errorCode
		}
		errorCodeName, ok := findStringInBson(responseSection.Body, "codeName")
		if ok {
			spanInfo.ErrorCodeName = errorCodeName
		}
	}

	return spanInfo, nil
}

func TCPToMongoToSpan(trace *TCPRequestInfo, info *mongoSpanInfo) request.Span {
	peer := ""
	peerPort := 0
	hostname := ""
	hostPort := 0

	reqType := request.EventTypeMongoClient

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		peerPort = int(trace.ConnInfo.S_port)
		hostPort = int(trace.ConnInfo.D_port)
	}

	var dbError request.DBError
	if !info.Success {
		dbError = request.DBError{
			ErrorCode:   strconv.Itoa(info.ErrorCode),
			Description: info.ErrorCodeName + ": " + info.Error,
		}
	}

	var status int
	if info.Success {
		status = 0
	} else {
		status = 1
	}

	return request.Span{
		Type:          reqType,
		Method:        info.OpName,
		Path:          info.Collection,
		Peer:          peer,
		PeerPort:      peerPort,
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: int64(trace.ReqLen),
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        status,
		DBError:       dbError,
		DBNamespace:   info.DB,
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}

func isHeartbeat(comm string) bool {
	return comm == commHello || comm == commIsMaster || comm == commPing || comm == commIsWritablePrimary || comm == commAtlasVersion
}

func isCollectionCommand(comm string) bool {
	return comm == commInsert || comm == commUpdate || comm == commFind || comm == commDelete ||
		comm == commFindAndModify || comm == commAggregate || comm == commCount || comm == commDistinct ||
		comm == commMapReduce
}

func parseFirstField(field bson.E) (string, string, error) {
	comm := field.Key
	if isHeartbeat(comm) {
		return "", "", fmt.Errorf("MongoDB heartbeat operation '%s' is ignored", comm)
	}
	if isCollectionCommand(comm) {
		collection := field.Value.(string)
		return comm, collection, nil
	}
	return comm, "", nil
}

func findInBson(doc bson.D, key string) (any, bool) {
	for _, elem := range doc {
		if elem.Key == key {
			return elem.Value, true
		}
	}
	return nil, false
}

func findStringInBson(doc bson.D, key string) (string, bool) {
	value, found := findInBson(doc, key)
	if !found {
		return "", false
	}
	strValue, ok := value.(string)
	if !ok {
		return "", false
	}
	return strValue, true
}

func findIntInBson(doc bson.D, key string) (int, bool) {
	value, found := findInBson(doc, key)
	if !found {
		return 0, false
	}
	intValue, ok := value.(int) // MongoDB uses int32 for integer values
	if !ok {
		return 0, false
	}
	return intValue, true
}

func findDoubleInBson(doc bson.D, key string) (float64, bool) {
	value, found := findInBson(doc, key)
	if !found {
		return 0, false
	}
	doubleValue, ok := value.(float64) // MongoDB uses int32 for integer values
	if !ok {
		return 0, false
	}
	return doubleValue, true
}

func opAndCollectionFromEvent(event *GoMongoClientInfo) (string, string) {
	coll := cstr(event.Coll[:])
	db := cstr(event.Db[:])

	if db != "" {
		if coll == "" {
			coll = db
		} else {
			coll = db + "." + coll
		}
	}

	op := cstr(event.Op[:])

	return op, coll
}

func ReadGoMongoRequestIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ReinterpretCast[GoMongoClientInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	peer := ""
	hostname := ""
	hostPort := 0

	if event.Conn.S_port != 0 || event.Conn.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&event.Conn)).reqHostInfo()
		hostPort = int(event.Conn.D_port)
	}

	op, coll := opAndCollectionFromEvent(event)

	// Mongo client sends these dummy hello requests all the time
	if op == "" {
		return request.Span{}, true, nil
	}

	return request.Span{
		Type:          request.EventTypeMongoClient, // always client for Go
		Method:        op,
		Path:          coll,
		Peer:          peer,
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(event.StartMonotimeNs),
		Start:         int64(event.StartMonotimeNs),
		End:           int64(event.EndMonotimeNs),
		Status:        int(event.Err),
		TraceID:       trace2.TraceID(event.Tp.TraceId),
		SpanID:        trace2.SpanID(event.Tp.SpanId),
		ParentSpanID:  trace2.SpanID(event.Tp.ParentId),
		TraceFlags:    event.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   event.Pid.HostPid,
			UserPID:   event.Pid.UserPid,
			Namespace: event.Pid.Ns,
		},
	}, false, nil
}
