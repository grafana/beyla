// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"unsafe"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/couchbasekv"
)

// CouchbaseInfo holds parsed Couchbase memcached binary protocol information.
type CouchbaseInfo struct {
	Operation  string
	Key        string
	Bucket     string
	Scope      string
	Collection string
	Status     couchbasekv.Status
	IsError    bool
}

// ProcessPossibleCouchbaseEvent attempts to parse the event as a Couchbase memcached binary protocol event.
// Returns a slice of CouchbaseInfo if successful, along with a boolean indicating if the event should be ignored,
// and an error if parsing failed. Multiple packets may be present in a single TCP segment due to pipelining.
func ProcessPossibleCouchbaseEvent(event *TCPRequestInfo, requestBuf []byte, responseBuf []byte, bucketCache *simplelru.LRU[BpfConnectionInfoT, CouchbaseBucketInfo]) (*CouchbaseInfo, bool, error) {
	info, ignore, err := processCouchbaseEvent(event.ConnInfo, requestBuf, responseBuf, bucketCache)
	// If parsing failed (error or no valid packets found), try with buffers reversed
	if err != nil {
		// Try with buffers reversed - we might have captured it backwards
		info, ignore, err = processCouchbaseEvent(event.ConnInfo, responseBuf, requestBuf, bucketCache)
		if err == nil {
			reverseTCPEvent(event)
			return info, false, nil
		}
	}
	return info, ignore, err
}

// handleSelectBucket processes the SELECT_BUCKET command and updates the bucket cache.
func handleSelectBucket(connInfo BpfConnectionInfoT, reqPacket *couchbasekv.Packet, responseBuf []byte, bucketCache *simplelru.LRU[BpfConnectionInfoT, CouchbaseBucketInfo]) {
	respPacket, respErr := couchbasekv.ParsePacket(responseBuf)
	if respErr != nil {
		return
	}
	handleSelectBucketWithResponse(connInfo, reqPacket, respPacket, bucketCache)
}

// handleSelectBucketWithResponse processes the SELECT_BUCKET command with an already-parsed response.
func handleSelectBucketWithResponse(connInfo BpfConnectionInfoT, reqPacket *couchbasekv.Packet, respPacket *couchbasekv.Packet, bucketCache *simplelru.LRU[BpfConnectionInfoT, CouchbaseBucketInfo]) {
	bucketName := reqPacket.KeyString()
	if bucketCache == nil || bucketName == "" {
		return
	}

	// Check if bucket selection was successful
	// there might be cases where the response is nil (e.g., truncated), we assume success
	if respPacket != nil && (!respPacket.IsResponse() || !respPacket.Header.Status.IsSuccess()) {
		return
	}

	bucketInfo, found := bucketCache.Get(connInfo)
	if !found {
		bucketInfo = CouchbaseBucketInfo{}
	}
	bucketInfo.Bucket = bucketName
	slog.Debug("Adding Couchbase bucket to cache", "bucket", bucketName, "conn", connInfo)
	bucketCache.Add(connInfo, bucketInfo)
}

// handleGetCollectionID processes the GET_COLLECTION_ID command and updates the bucket cache with scope/collection.
func handleGetCollectionID(connInfo BpfConnectionInfoT, reqPacket *couchbasekv.Packet, responseBuf []byte, bucketCache *simplelru.LRU[BpfConnectionInfoT, CouchbaseBucketInfo]) {
	// Parse response to check if collection lookup was successful
	respPacket, respErr := couchbasekv.ParsePacket(responseBuf)
	if respErr != nil {
		return
	}
	handleGetCollectionIDWithResponse(connInfo, reqPacket, respPacket, bucketCache)
}

// handleGetCollectionIDWithResponse processes the GET_COLLECTION_ID command with an already-parsed response.
func handleGetCollectionIDWithResponse(connInfo BpfConnectionInfoT, reqPacket *couchbasekv.Packet, respPacket *couchbasekv.Packet, bucketCache *simplelru.LRU[BpfConnectionInfoT, CouchbaseBucketInfo]) {
	scopeCollection := reqPacket.ValueString()
	if bucketCache == nil || scopeCollection == "" {
		return
	}

	// Check if collection lookup was successful
	if respPacket == nil || !respPacket.IsResponse() || !respPacket.Header.Status.IsSuccess() {
		return
	}

	// Parse scope.collection from the value
	parts := strings.SplitN(scopeCollection, ".", 2)
	if len(parts) != 2 {
		slog.Debug("Couchbase GET_COLLECTION_ID: invalid scope.collection format, skipping", "scope_collection", scopeCollection, "conn", connInfo)
		return
	}

	// Get existing bucket info or create new one
	bucketInfo, found := bucketCache.Get(connInfo)
	if !found {
		bucketInfo = CouchbaseBucketInfo{}
	}
	bucketInfo.Scope = parts[0]
	bucketInfo.Collection = parts[1]
	slog.Debug("Updating Couchbase bucket cache with scope and collection", "scope", bucketInfo.Scope, "collection", bucketInfo.Collection, "conn", connInfo)
	bucketCache.Add(connInfo, bucketInfo)
}

// processCouchbaseEvent parses Couchbase packets from request and response buffers.
// It handles multiple packets that may be pipelined in a single TCP segment.
func processCouchbaseEvent(connInfo BpfConnectionInfoT, requestBuf []byte, responseBuf []byte, bucketCache *simplelru.LRU[BpfConnectionInfoT, CouchbaseBucketInfo]) (*CouchbaseInfo, bool, error) {
	reqPackets, err := couchbasekv.ParsePackets(requestBuf)
	if err != nil {
		return nil, true, err
	}

	// If no valid request packets, return early
	if len(reqPackets) == 0 {
		return nil, true, errors.New("no valid Couchbase request packets found")
	}

	// We need at least one request packet
	hasRequest := false
	for _, pkt := range reqPackets {
		if pkt.IsRequest() {
			hasRequest = true
			break
		}
	}
	if !hasRequest {
		return nil, true, nil
	}

	respPackets, _ := couchbasekv.ParsePackets(responseBuf)

	// Build a map of response packets by Opaque for matching
	respByOpaque := make(map[uint32]*couchbasekv.Packet)
	for _, pkt := range respPackets {
		if pkt.IsResponse() {
			respByOpaque[pkt.Header.Opaque] = pkt
		}
	}

	for _, reqPacket := range reqPackets {
		if !reqPacket.IsRequest() {
			continue
		}

		respPacket := respByOpaque[reqPacket.Header.Opaque]

		if reqPacket.Header.Opcode == couchbasekv.OpcodeSelectBucket {
			handleSelectBucketWithResponse(connInfo, reqPacket, respPacket, bucketCache)
			// Don't create a span for SELECT_BUCKET
			continue
		}

		if reqPacket.Header.Opcode == couchbasekv.OpcodeCollectionsGetID {
			handleGetCollectionIDWithResponse(connInfo, reqPacket, respPacket, bucketCache)
			// Don't create a span for GET_COLLECTION_ID
			continue
		}

		if !reqPacket.Header.Opcode.IsKVOperation() {
			slog.Debug("Ignoring non-KV Couchbase operation", "opcode", reqPacket.Header.Opcode.String())
			continue
		}

		info := &CouchbaseInfo{
			Operation: reqPacket.Header.Opcode.String(),
			Key:       reqPacket.KeyString(),
		}

		// Get bucket info from cache
		if bucketCache != nil {
			if bucketInfo, found := bucketCache.Get(connInfo); found {
				info.Bucket = bucketInfo.Bucket
				info.Scope = bucketInfo.Scope
				info.Collection = bucketInfo.Collection
			}
		}

		if respPacket != nil && respPacket.IsResponse() {
			info.Status = respPacket.Header.Status
			info.IsError = respPacket.Header.Status.IsError()
		}

		return info, false, nil
	}
	return nil, true, nil
}

// TCPToCouchbaseToSpan converts a TCP event with Couchbase data to a request.Span.
func TCPToCouchbaseToSpan(trace *TCPRequestInfo, data *CouchbaseInfo) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	reqType := request.EventTypeCouchbaseClient

	status := 0
	var dbError request.DBError
	if data.IsError {
		status = int(data.Status)
		dbError = request.DBError{
			ErrorCode:   strconv.Itoa(status),
			Description: data.Status.String(),
		}
	}

	// Build the database namespace: bucket.scope
	dbNamespace := data.Bucket

	collection := data.Scope
	if collection == "" {
		collection = data.Collection
	} else if data.Collection != "" {
		collection += "." + data.Collection
	}

	return request.Span{
		Type:          reqType,
		Method:        data.Operation,
		Path:          collection,
		Peer:          peer,
		PeerPort:      int(trace.ConnInfo.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        status,
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
		DBError:     dbError,
		DBNamespace: dbNamespace,
	}
}
