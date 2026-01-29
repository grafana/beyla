// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package couchbasekv // import "go.opentelemetry.io/obi/pkg/internal/ebpf/couchbasekv"

// Header sizes
const (
	HeaderLen = 24 // All packets have a 24-byte header
)

// Magic bytes identify packet direction and encoding format
type Magic uint8

const (
	MagicClientRequest     Magic = 0x80 // Client → Server request
	MagicAltClientRequest  Magic = 0x08 // Client → Server request (alternative frame format)
	MagicClientResponse    Magic = 0x81 // Server → Client response
	MagicAltClientResponse Magic = 0x18 // Server → Client response (alternative frame format)
	MagicServerRequest     Magic = 0x82 // Server → Client request (e.g., for replication)
	MagicServerResponse    Magic = 0x83 // Client → Server response
)

// IsRequest returns true if this magic byte indicates a request packet.
func (m Magic) IsRequest() bool {
	return m == MagicClientRequest || m == MagicAltClientRequest || m == MagicServerRequest
}

// IsResponse returns true if this magic byte indicates a response packet.
func (m Magic) IsResponse() bool {
	return m == MagicClientResponse || m == MagicAltClientResponse || m == MagicServerResponse
}

// IsAltFormat returns true if this magic byte uses the alternative frame format.
func (m Magic) IsAltFormat() bool {
	return m == MagicAltClientRequest || m == MagicAltClientResponse
}

// IsValid returns true if this is a valid magic byte.
func (m Magic) IsValid() bool {
	return m == MagicClientRequest || m == MagicAltClientRequest ||
		m == MagicClientResponse || m == MagicAltClientResponse ||
		m == MagicServerRequest || m == MagicServerResponse
}

func (m Magic) String() string {
	switch m {
	case MagicClientRequest:
		return "ClientRequest"
	case MagicAltClientRequest:
		return "AltClientRequest"
	case MagicClientResponse:
		return "ClientResponse"
	case MagicAltClientResponse:
		return "AltClientResponse"
	case MagicServerRequest:
		return "ServerRequest"
	case MagicServerResponse:
		return "ServerResponse"
	default:
		return "Unknown"
	}
}

// Opcode identifies the command type
type Opcode uint8

const (
	// Basic key-value operations
	OpcodeGet        Opcode = 0x00
	OpcodeSet        Opcode = 0x01
	OpcodeAdd        Opcode = 0x02
	OpcodeReplace    Opcode = 0x03
	OpcodeDelete     Opcode = 0x04
	OpcodeIncrement  Opcode = 0x05
	OpcodeDecrement  Opcode = 0x06
	OpcodeQuit       Opcode = 0x07
	OpcodeFlush      Opcode = 0x08 // Unsupported
	OpcodeGetQ       Opcode = 0x09 // Get quietly (no response on miss)
	OpcodeNoop       Opcode = 0x0a
	OpcodeVersion    Opcode = 0x0b
	OpcodeGetK       Opcode = 0x0c // Get with key in response
	OpcodeGetKQ      Opcode = 0x0d // Get with key, quietly
	OpcodeAppend     Opcode = 0x0e
	OpcodePrepend    Opcode = 0x0f
	OpcodeStat       Opcode = 0x10
	OpcodeSetQ       Opcode = 0x11 // Set quietly
	OpcodeAddQ       Opcode = 0x12 // Add quietly
	OpcodeReplaceQ   Opcode = 0x13 // Replace quietly
	OpcodeDeleteQ    Opcode = 0x14 // Delete quietly
	OpcodeIncrementQ Opcode = 0x15 // Increment quietly
	OpcodeDecrementQ Opcode = 0x16 // Decrement quietly
	OpcodeQuitQ      Opcode = 0x17 // Quit quietly
	OpcodeFlushQ     Opcode = 0x18 // Flush quietly (unsupported)
	OpcodeAppendQ    Opcode = 0x19 // Append quietly
	OpcodePrependQ   Opcode = 0x1a // Prepend quietly
	OpcodeVerbosity  Opcode = 0x1b
	OpcodeTouch      Opcode = 0x1c
	OpcodeGAT        Opcode = 0x1d // Get and touch
	OpcodeGATQ       Opcode = 0x1e // Get and touch quietly

	// SASL authentication
	OpcodeHello         Opcode = 0x1f // Feature negotiation
	OpcodeSASLListMechs Opcode = 0x20
	OpcodeSASLAuth      Opcode = 0x21
	OpcodeSASLStep      Opcode = 0x22

	// Server management
	OpcodeIoctlGet                    Opcode = 0x23
	OpcodeIoctlSet                    Opcode = 0x24
	OpcodeConfigValidate              Opcode = 0x25
	OpcodeConfigReload                Opcode = 0x26
	OpcodeAuditPut                    Opcode = 0x27
	OpcodeAuditConfigReload           Opcode = 0x28
	OpcodeShutdown                    Opcode = 0x29
	OpcodeSetBucketThrottleProperties Opcode = 0x2a
	OpcodeSetBucketDataLimitExceeded  Opcode = 0x2b
	OpcodeSetNodeThrottleProperties   Opcode = 0x2c // Unsupported
	OpcodeSetActiveEncryptionKeys     Opcode = 0x2d
	OpcodePruneEncryptionKeys         Opcode = 0x2e
	OpcodeRegisterAuthToken           Opcode = 0x2f

	// VBucket operations
	OpcodeSetVBucket Opcode = 0x3d
	OpcodeGetVBucket Opcode = 0x3e
	OpcodeDelVBucket Opcode = 0x3f

	// Sequence numbers
	OpcodeGetAllVbSeqnos Opcode = 0x48
	OpcodeGetEx          Opcode = 0x49
	OpcodeGetExReplica   Opcode = 0x4a

	// DCP (Database Change Protocol)
	OpcodeDcpOpen                  Opcode = 0x50
	OpcodeDcpAddStream             Opcode = 0x51
	OpcodeDcpCloseStream           Opcode = 0x52
	OpcodeDcpStreamReq             Opcode = 0x53
	OpcodeDcpGetFailoverLog        Opcode = 0x54
	OpcodeDcpStreamEnd             Opcode = 0x55
	OpcodeDcpSnapshotMarker        Opcode = 0x56
	OpcodeDcpMutation              Opcode = 0x57
	OpcodeDcpDeletion              Opcode = 0x58
	OpcodeDcpExpiration            Opcode = 0x59
	OpcodeDcpFlush                 Opcode = 0x5a // Unsupported
	OpcodeDcpSetVbucketState       Opcode = 0x5b
	OpcodeDcpNoop                  Opcode = 0x5c
	OpcodeDcpBufferAcknowledgement Opcode = 0x5d
	OpcodeDcpControl               Opcode = 0x5e
	OpcodeDcpSystemEvent           Opcode = 0x5f
	OpcodeDcpPrepare               Opcode = 0x60
	OpcodeDcpSeqnoAcknowledged     Opcode = 0x61
	OpcodeDcpCommit                Opcode = 0x62
	OpcodeDcpAbort                 Opcode = 0x63
	OpcodeDcpSeqnoAdvanced         Opcode = 0x64
	OpcodeDcpOsoSnapshot           Opcode = 0x65
	OpcodeDcpCachedValue           Opcode = 0x66
	OpcodeDcpCachedKeyMeta         Opcode = 0x67
	OpcodeDcpCacheTransferEnd      Opcode = 0x68

	// Fusion Storage
	OpcodeGetFusionStorageSnapshot     Opcode = 0x70
	OpcodeReleaseFusionStorageSnapshot Opcode = 0x71
	OpcodeMountFusionVbucket           Opcode = 0x72
	OpcodeUnmountFusionVbucket         Opcode = 0x73
	OpcodeSyncFusionLogstore           Opcode = 0x74
	OpcodeStartFusionUploader          Opcode = 0x75
	OpcodeStopFusionUploader           Opcode = 0x76
	OpcodeDeleteFusionNamespace        Opcode = 0x77
	OpcodeGetFusionNamespaces          Opcode = 0x78

	// Persistence and bucket management
	OpcodeStopPersistence       Opcode = 0x80
	OpcodeStartPersistence      Opcode = 0x81
	OpcodeSetParam              Opcode = 0x82
	OpcodeGetReplica            Opcode = 0x83
	OpcodeSetChronicleAuthToken Opcode = 0x84
	OpcodeCreateBucket          Opcode = 0x85
	OpcodeDeleteBucket          Opcode = 0x86
	OpcodeListBuckets           Opcode = 0x87
	OpcodeSelectBucket          Opcode = 0x89
	OpcodePauseBucket           Opcode = 0x8a
	OpcodeResumeBucket          Opcode = 0x8b
	OpcodeValidateBucketConfig  Opcode = 0x8c

	// Observe and locking
	OpcodeObserveSeqno   Opcode = 0x91
	OpcodeObserve        Opcode = 0x92
	OpcodeEvictKey       Opcode = 0x93
	OpcodeGetLocked      Opcode = 0x94
	OpcodeUnlockKey      Opcode = 0x95
	OpcodeGetFailoverLog Opcode = 0x96

	// Metadata operations
	OpcodeGetMeta      Opcode = 0xa0
	OpcodeGetQMeta     Opcode = 0xa1
	OpcodeSetWithMeta  Opcode = 0xa2
	OpcodeSetQWithMeta Opcode = 0xa3
	OpcodeAddWithMeta  Opcode = 0xa4
	OpcodeAddQWithMeta Opcode = 0xa5
	OpcodeDelWithMeta  Opcode = 0xa8
	OpcodeDelQWithMeta Opcode = 0xa9

	// Traffic and cluster management
	OpcodeEnableTraffic    Opcode = 0xad
	OpcodeDisableTraffic   Opcode = 0xae
	OpcodeIfconfig         Opcode = 0xaf
	OpcodeReturnMeta       Opcode = 0xb2
	OpcodeCompactDB        Opcode = 0xb3
	OpcodeSetClusterConfig Opcode = 0xb4
	OpcodeGetClusterConfig Opcode = 0xb5
	OpcodeGetRandomKey     Opcode = 0xb6
	OpcodeSeqnoPersistence Opcode = 0xb7
	OpcodeGetKeys          Opcode = 0xb8

	// Collections
	OpcodeCollectionsSetManifest Opcode = 0xb9
	OpcodeCollectionsGetManifest Opcode = 0xba
	OpcodeCollectionsGetID       Opcode = 0xbb
	OpcodeCollectionsGetScopeID  Opcode = 0xbc

	// Sub-document operations
	OpcodeSubdocGet                  Opcode = 0xc5
	OpcodeSubdocExists               Opcode = 0xc6
	OpcodeSubdocDictAdd              Opcode = 0xc7
	OpcodeSubdocDictUpsert           Opcode = 0xc8
	OpcodeSubdocDelete               Opcode = 0xc9
	OpcodeSubdocReplace              Opcode = 0xca
	OpcodeSubdocArrayPushLast        Opcode = 0xcb
	OpcodeSubdocArrayPushFirst       Opcode = 0xcc
	OpcodeSubdocArrayInsert          Opcode = 0xcd
	OpcodeSubdocArrayAddUnique       Opcode = 0xce
	OpcodeSubdocCounter              Opcode = 0xcf
	OpcodeSubdocMultiLookup          Opcode = 0xd0
	OpcodeSubdocMultiMutation        Opcode = 0xd1
	OpcodeSubdocGetCount             Opcode = 0xd2
	OpcodeSubdocReplaceBodyWithXattr Opcode = 0xd3

	// Range scan operations
	OpcodeRangeScanCreate   Opcode = 0xda
	OpcodeRangeScanContinue Opcode = 0xdb
	OpcodeRangeScanCancel   Opcode = 0xdc

	// Snapshot operations
	OpcodePrepareSnapshot  Opcode = 0xe0
	OpcodeReleaseSnapshot  Opcode = 0xe1
	OpcodeDownloadSnapshot Opcode = 0xe2
	OpcodeGetFileFragment  Opcode = 0xe3

	// Administrative
	OpcodeIsaslRefresh                  Opcode = 0xf1
	OpcodeGetCmdTimer                   Opcode = 0xf3
	OpcodeSetCtrlToken                  Opcode = 0xf4
	OpcodeGetCtrlToken                  Opcode = 0xf5
	OpcodeUpdateExternalUserPermissions Opcode = 0xf6
	OpcodeRbacRefresh                   Opcode = 0xf7
	OpcodeAuthProvider                  Opcode = 0xf8
	OpcodeDropPrivilege                 Opcode = 0xfb
	OpcodeAdjustTimeofday               Opcode = 0xfc
	OpcodeEwouldblockCtl                Opcode = 0xfd
	OpcodeGetErrorMap                   Opcode = 0xfe
	OpcodeInvalid                       Opcode = 0xff
)

func (o Opcode) String() string {
	switch o {
	// Basic key-value operations
	case OpcodeGet:
		return "GET"
	case OpcodeSet:
		return "SET"
	case OpcodeAdd:
		return "ADD"
	case OpcodeReplace:
		return "REPLACE"
	case OpcodeDelete:
		return "DELETE"
	case OpcodeIncrement:
		return "INCREMENT"
	case OpcodeDecrement:
		return "DECREMENT"
	case OpcodeQuit:
		return "QUIT"
	case OpcodeFlush:
		return "FLUSH"
	case OpcodeGetQ:
		return "GETQ"
	case OpcodeNoop:
		return "NOOP"
	case OpcodeVersion:
		return "VERSION"
	case OpcodeGetK:
		return "GETK"
	case OpcodeGetKQ:
		return "GETKQ"
	case OpcodeAppend:
		return "APPEND"
	case OpcodePrepend:
		return "PREPEND"
	case OpcodeStat:
		return "STAT"
	case OpcodeSetQ:
		return "SETQ"
	case OpcodeAddQ:
		return "ADDQ"
	case OpcodeReplaceQ:
		return "REPLACEQ"
	case OpcodeDeleteQ:
		return "DELETEQ"
	case OpcodeIncrementQ:
		return "INCREMENTQ"
	case OpcodeDecrementQ:
		return "DECREMENTQ"
	case OpcodeQuitQ:
		return "QUITQ"
	case OpcodeFlushQ:
		return "FLUSHQ"
	case OpcodeAppendQ:
		return "APPENDQ"
	case OpcodePrependQ:
		return "PREPENDQ"
	case OpcodeVerbosity:
		return "VERBOSITY"
	case OpcodeTouch:
		return "TOUCH"
	case OpcodeGAT:
		return "GAT"
	case OpcodeGATQ:
		return "GATQ"

	// SASL authentication
	case OpcodeHello:
		return "HELLO"
	case OpcodeSASLListMechs:
		return "SASL_LIST_MECHS"
	case OpcodeSASLAuth:
		return "SASL_AUTH"
	case OpcodeSASLStep:
		return "SASL_STEP"

	// Server management
	case OpcodeIoctlGet:
		return "IOCTL_GET"
	case OpcodeIoctlSet:
		return "IOCTL_SET"
	case OpcodeConfigValidate:
		return "CONFIG_VALIDATE"
	case OpcodeConfigReload:
		return "CONFIG_RELOAD"
	case OpcodeAuditPut:
		return "AUDIT_PUT"
	case OpcodeAuditConfigReload:
		return "AUDIT_CONFIG_RELOAD"
	case OpcodeShutdown:
		return "SHUTDOWN"
	case OpcodeSetBucketThrottleProperties:
		return "SET_BUCKET_THROTTLE_PROPERTIES"
	case OpcodeSetBucketDataLimitExceeded:
		return "SET_BUCKET_DATA_LIMIT_EXCEEDED"
	case OpcodeSetNodeThrottleProperties:
		return "SET_NODE_THROTTLE_PROPERTIES"
	case OpcodeSetActiveEncryptionKeys:
		return "SET_ACTIVE_ENCRYPTION_KEYS"
	case OpcodePruneEncryptionKeys:
		return "PRUNE_ENCRYPTION_KEYS"
	case OpcodeRegisterAuthToken:
		return "REGISTER_AUTH_TOKEN"

	// VBucket operations
	case OpcodeSetVBucket:
		return "SET_VBUCKET"
	case OpcodeGetVBucket:
		return "GET_VBUCKET"
	case OpcodeDelVBucket:
		return "DEL_VBUCKET"

	// Sequence numbers
	case OpcodeGetAllVbSeqnos:
		return "GET_ALL_VB_SEQNOS"
	case OpcodeGetEx:
		return "GET_EX"
	case OpcodeGetExReplica:
		return "GET_EX_REPLICA"

	// DCP operations
	case OpcodeDcpOpen:
		return "DCP_OPEN"
	case OpcodeDcpAddStream:
		return "DCP_ADD_STREAM"
	case OpcodeDcpCloseStream:
		return "DCP_CLOSE_STREAM"
	case OpcodeDcpStreamReq:
		return "DCP_STREAM_REQ"
	case OpcodeDcpGetFailoverLog:
		return "DCP_GET_FAILOVER_LOG"
	case OpcodeDcpStreamEnd:
		return "DCP_STREAM_END"
	case OpcodeDcpSnapshotMarker:
		return "DCP_SNAPSHOT_MARKER"
	case OpcodeDcpMutation:
		return "DCP_MUTATION"
	case OpcodeDcpDeletion:
		return "DCP_DELETION"
	case OpcodeDcpExpiration:
		return "DCP_EXPIRATION"
	case OpcodeDcpFlush:
		return "DCP_FLUSH"
	case OpcodeDcpSetVbucketState:
		return "DCP_SET_VBUCKET_STATE"
	case OpcodeDcpNoop:
		return "DCP_NOOP"
	case OpcodeDcpBufferAcknowledgement:
		return "DCP_BUFFER_ACKNOWLEDGEMENT"
	case OpcodeDcpControl:
		return "DCP_CONTROL"
	case OpcodeDcpSystemEvent:
		return "DCP_SYSTEM_EVENT"
	case OpcodeDcpPrepare:
		return "DCP_PREPARE"
	case OpcodeDcpSeqnoAcknowledged:
		return "DCP_SEQNO_ACKNOWLEDGED"
	case OpcodeDcpCommit:
		return "DCP_COMMIT"
	case OpcodeDcpAbort:
		return "DCP_ABORT"
	case OpcodeDcpSeqnoAdvanced:
		return "DCP_SEQNO_ADVANCED"
	case OpcodeDcpOsoSnapshot:
		return "DCP_OSO_SNAPSHOT"
	case OpcodeDcpCachedValue:
		return "DCP_CACHED_VALUE"
	case OpcodeDcpCachedKeyMeta:
		return "DCP_CACHED_KEY_META"
	case OpcodeDcpCacheTransferEnd:
		return "DCP_CACHE_TRANSFER_END"

	// Fusion Storage
	case OpcodeGetFusionStorageSnapshot:
		return "GET_FUSION_STORAGE_SNAPSHOT"
	case OpcodeReleaseFusionStorageSnapshot:
		return "RELEASE_FUSION_STORAGE_SNAPSHOT"
	case OpcodeMountFusionVbucket:
		return "MOUNT_FUSION_VBUCKET"
	case OpcodeUnmountFusionVbucket:
		return "UNMOUNT_FUSION_VBUCKET"
	case OpcodeSyncFusionLogstore:
		return "SYNC_FUSION_LOGSTORE"
	case OpcodeStartFusionUploader:
		return "START_FUSION_UPLOADER"
	case OpcodeStopFusionUploader:
		return "STOP_FUSION_UPLOADER"
	case OpcodeDeleteFusionNamespace:
		return "DELETE_FUSION_NAMESPACE"
	case OpcodeGetFusionNamespaces:
		return "GET_FUSION_NAMESPACES"

	// Persistence and bucket management
	case OpcodeStopPersistence:
		return "STOP_PERSISTENCE"
	case OpcodeStartPersistence:
		return "START_PERSISTENCE"
	case OpcodeSetParam:
		return "SET_PARAM"
	case OpcodeGetReplica:
		return "GET_REPLICA"
	case OpcodeSetChronicleAuthToken:
		return "SET_CHRONICLE_AUTH_TOKEN"
	case OpcodeCreateBucket:
		return "CREATE_BUCKET"
	case OpcodeDeleteBucket:
		return "DELETE_BUCKET"
	case OpcodeListBuckets:
		return "LIST_BUCKETS"
	case OpcodeSelectBucket:
		return "SELECT_BUCKET"
	case OpcodePauseBucket:
		return "PAUSE_BUCKET"
	case OpcodeResumeBucket:
		return "RESUME_BUCKET"
	case OpcodeValidateBucketConfig:
		return "VALIDATE_BUCKET_CONFIG"

	// Observe and locking
	case OpcodeObserveSeqno:
		return "OBSERVE_SEQNO"
	case OpcodeObserve:
		return "OBSERVE"
	case OpcodeEvictKey:
		return "EVICT_KEY"
	case OpcodeGetLocked:
		return "GET_LOCKED"
	case OpcodeUnlockKey:
		return "UNLOCK_KEY"
	case OpcodeGetFailoverLog:
		return "GET_FAILOVER_LOG"

	// Metadata operations
	case OpcodeGetMeta:
		return "GET_META"
	case OpcodeGetQMeta:
		return "GETQ_META"
	case OpcodeSetWithMeta:
		return "SET_WITH_META"
	case OpcodeSetQWithMeta:
		return "SETQ_WITH_META"
	case OpcodeAddWithMeta:
		return "ADD_WITH_META"
	case OpcodeAddQWithMeta:
		return "ADDQ_WITH_META"
	case OpcodeDelWithMeta:
		return "DEL_WITH_META"
	case OpcodeDelQWithMeta:
		return "DELQ_WITH_META"

	// Traffic and cluster management
	case OpcodeEnableTraffic:
		return "ENABLE_TRAFFIC"
	case OpcodeDisableTraffic:
		return "DISABLE_TRAFFIC"
	case OpcodeIfconfig:
		return "IFCONFIG"
	case OpcodeReturnMeta:
		return "RETURN_META"
	case OpcodeCompactDB:
		return "COMPACT_DB"
	case OpcodeSetClusterConfig:
		return "SET_CLUSTER_CONFIG"
	case OpcodeGetClusterConfig:
		return "GET_CLUSTER_CONFIG"
	case OpcodeGetRandomKey:
		return "GET_RANDOM_KEY"
	case OpcodeSeqnoPersistence:
		return "SEQNO_PERSISTENCE"
	case OpcodeGetKeys:
		return "GET_KEYS"

	// Collections
	case OpcodeCollectionsSetManifest:
		return "COLLECTIONS_SET_MANIFEST"
	case OpcodeCollectionsGetManifest:
		return "COLLECTIONS_GET_MANIFEST"
	case OpcodeCollectionsGetID:
		return "COLLECTIONS_GET_ID"
	case OpcodeCollectionsGetScopeID:
		return "COLLECTIONS_GET_SCOPE_ID"

	// Sub-document operations
	case OpcodeSubdocGet:
		return "SUBDOC_GET"
	case OpcodeSubdocExists:
		return "SUBDOC_EXISTS"
	case OpcodeSubdocDictAdd:
		return "SUBDOC_DICT_ADD"
	case OpcodeSubdocDictUpsert:
		return "SUBDOC_DICT_UPSERT"
	case OpcodeSubdocDelete:
		return "SUBDOC_DELETE"
	case OpcodeSubdocReplace:
		return "SUBDOC_REPLACE"
	case OpcodeSubdocArrayPushLast:
		return "SUBDOC_ARRAY_PUSH_LAST"
	case OpcodeSubdocArrayPushFirst:
		return "SUBDOC_ARRAY_PUSH_FIRST"
	case OpcodeSubdocArrayInsert:
		return "SUBDOC_ARRAY_INSERT"
	case OpcodeSubdocArrayAddUnique:
		return "SUBDOC_ARRAY_ADD_UNIQUE"
	case OpcodeSubdocCounter:
		return "SUBDOC_COUNTER"
	case OpcodeSubdocMultiLookup:
		return "SUBDOC_MULTI_LOOKUP"
	case OpcodeSubdocMultiMutation:
		return "SUBDOC_MULTI_MUTATION"
	case OpcodeSubdocGetCount:
		return "SUBDOC_GET_COUNT"
	case OpcodeSubdocReplaceBodyWithXattr:
		return "SUBDOC_REPLACE_BODY_WITH_XATTR"

	// Range scan operations
	case OpcodeRangeScanCreate:
		return "RANGE_SCAN_CREATE"
	case OpcodeRangeScanContinue:
		return "RANGE_SCAN_CONTINUE"
	case OpcodeRangeScanCancel:
		return "RANGE_SCAN_CANCEL"

	// Snapshot operations
	case OpcodePrepareSnapshot:
		return "PREPARE_SNAPSHOT"
	case OpcodeReleaseSnapshot:
		return "RELEASE_SNAPSHOT"
	case OpcodeDownloadSnapshot:
		return "DOWNLOAD_SNAPSHOT"
	case OpcodeGetFileFragment:
		return "GET_FILE_FRAGMENT"

	// Administrative
	case OpcodeIsaslRefresh:
		return "ISASL_REFRESH"
	case OpcodeGetCmdTimer:
		return "GET_CMD_TIMER"
	case OpcodeSetCtrlToken:
		return "SET_CTRL_TOKEN"
	case OpcodeGetCtrlToken:
		return "GET_CTRL_TOKEN"
	case OpcodeUpdateExternalUserPermissions:
		return "UPDATE_EXTERNAL_USER_PERMISSIONS"
	case OpcodeRbacRefresh:
		return "RBAC_REFRESH"
	case OpcodeAuthProvider:
		return "AUTH_PROVIDER"
	case OpcodeDropPrivilege:
		return "DROP_PRIVILEGE"
	case OpcodeAdjustTimeofday:
		return "ADJUST_TIMEOFDAY"
	case OpcodeEwouldblockCtl:
		return "EWOULDBLOCK_CTL"
	case OpcodeGetErrorMap:
		return "GET_ERROR_MAP"
	case OpcodeInvalid:
		return "INVALID"
	default:
		return "UNKNOWN"
	}
}

func (o Opcode) IsKVOperation() bool {
	switch o {
	case OpcodeGet, OpcodeSet, OpcodeAdd, OpcodeReplace, OpcodeDelete,
		OpcodeIncrement, OpcodeDecrement, OpcodeGetK, OpcodeAppend,
		OpcodePrepend, OpcodeTouch, OpcodeGAT,
		OpcodeGetMeta, OpcodeSetWithMeta, OpcodeAddWithMeta, OpcodeDelWithMeta,
		OpcodeGetQ, OpcodeGetKQ, OpcodeSetQ, OpcodeAddQ, OpcodeReplaceQ,
		OpcodeDeleteQ, OpcodeIncrementQ, OpcodeDecrementQ,
		OpcodeFlushQ, OpcodeAppendQ, OpcodePrependQ, OpcodeGATQ,
		OpcodeGetQMeta, OpcodeSetQWithMeta, OpcodeAddQWithMeta, OpcodeDelQWithMeta:
		return true
	default:
		return false
	}
}

// Status codes for response packets
type Status uint16

const (
	// Success
	StatusSuccess Status = 0x0000

	// Key/value errors
	StatusKeyNotFound       Status = 0x0001 // Key does not exist
	StatusKeyExists         Status = 0x0002 // Key already exists
	StatusValueTooLarge     Status = 0x0003 // Value too large
	StatusInvalidArguments  Status = 0x0004 // Invalid arguments
	StatusItemNotStored     Status = 0x0005 // Item not stored
	StatusNonNumeric        Status = 0x0006 // Incr/decr on non-numeric value
	StatusVBucketNotHere    Status = 0x0007 // VBucket belongs to another server
	StatusNoBucket          Status = 0x0008 // Not connected to bucket
	StatusLocked            Status = 0x0009 // Document is locked
	StatusDcpStreamNotFound Status = 0x000a // DCP stream not found
	StatusOpaqueNoMatch     Status = 0x000b // Opaque does not match
	StatusEWouldThrottle    Status = 0x000c // Would be throttled
	StatusEConfigOnly       Status = 0x000d // Config only
	StatusNotLocked         Status = 0x000e // Document is not locked
	StatusCasValueInvalid   Status = 0x000f // CAS value is invalid

	// Authentication errors
	StatusAuthStale                 Status = 0x001f // Auth context is stale
	StatusAuthError                 Status = 0x0020 // Authentication error
	StatusAuthContinue              Status = 0x0021 // Authentication continue
	StatusOutOfRange                Status = 0x0022 // Value outside legal ranges
	StatusRollback                  Status = 0x0023 // Rollback required
	StatusNoAccess                  Status = 0x0024 // No access
	StatusNotInitialized            Status = 0x0025 // Not initialized
	StatusEncryptionKeyNotAvailable Status = 0x0026 // Encryption key not available
	StatusChecksumMismatch          Status = 0x0027 // Checksum mismatch

	// Rate limiting errors
	StatusRateLimitedNetworkIngress Status = 0x0030 // Rate limited: network ingress
	StatusRateLimitedNetworkEgress  Status = 0x0031 // Rate limited: network egress
	StatusRateLimitedMaxConnections Status = 0x0032 // Rate limited: max connections
	StatusRateLimitedMaxCommands    Status = 0x0033 // Rate limited: max commands
	StatusBucketSizeLimitExceeded   Status = 0x0035 // Bucket size limit exceeded
	StatusBucketResidentRatioTooLow Status = 0x0036 // Bucket resident ratio too low
	StatusBucketDataSizeTooBig      Status = 0x0037 // Bucket data size too big
	StatusBucketDiskSpaceTooLow     Status = 0x0038 // Bucket disk space too low

	// Bucket state errors
	StatusBucketPaused Status = 0x0050 // Bucket is paused
	StatusCancelled    Status = 0x0051 // Operation was cancelled

	// General errors
	StatusUnknownFrameInfo Status = 0x0080 // Unknown frame info
	StatusUnknownCommand   Status = 0x0081 // Unknown command
	StatusOutOfMemory      Status = 0x0082 // Out of memory
	StatusNotSupported     Status = 0x0083 // Not supported
	StatusInternalError    Status = 0x0084 // Internal error
	StatusBusy             Status = 0x0085 // Server busy
	StatusTemporaryFailure Status = 0x0086 // Temporary failure
	StatusXattrInvalid     Status = 0x0087 // Invalid XATTR

	// Collection errors
	StatusUnknownCollection              Status = 0x0088 // Unknown collection
	StatusCannotApplyCollectionsManifest Status = 0x008a // Cannot apply collections manifest
	StatusUnknownScope                   Status = 0x008c // Unknown scope
	StatusDcpStreamIDInvalid             Status = 0x008d // DCP stream ID invalid

	// Durability errors
	StatusDurabilityInvalidLevel      Status = 0x00a0 // Invalid durability level
	StatusDurabilityImpossible        Status = 0x00a1 // Durability impossible
	StatusSyncWriteInProgress         Status = 0x00a2 // Sync write in progress
	StatusSyncWriteAmbiguous          Status = 0x00a3 // Sync write ambiguous
	StatusSyncWriteReCommitInProgress Status = 0x00a4 // Sync write re-commit in progress

	// Range scan status
	StatusRangeScanCancelled Status = 0x00a5 // Range scan cancelled
	StatusRangeScanMore      Status = 0x00a6 // Range scan more data available
	StatusRangeScanComplete  Status = 0x00a7 // Range scan complete
	StatusVbUUIDNotEqual     Status = 0x00a8 // VBucket UUID not equal

	// Sub-document errors
	StatusSubdocPathNotFound             Status = 0x00c0 // Path not found
	StatusSubdocPathMismatch             Status = 0x00c1 // Path mismatch
	StatusSubdocPathInvalid              Status = 0x00c2 // Path invalid
	StatusSubdocPathTooBig               Status = 0x00c3 // Path too big
	StatusSubdocDocTooDeep               Status = 0x00c4 // Document too deep
	StatusSubdocValueCantInsert          Status = 0x00c5 // Value can't be inserted
	StatusSubdocDocNotJSON               Status = 0x00c6 // Document not JSON
	StatusSubdocNumOutOfRange            Status = 0x00c7 // Number out of range
	StatusSubdocDeltaInvalid             Status = 0x00c8 // Delta invalid
	StatusSubdocPathExists               Status = 0x00c9 // Path already exists
	StatusSubdocValueTooDeep             Status = 0x00ca // Value too deep
	StatusSubdocInvalidCombo             Status = 0x00cb // Invalid combination
	StatusSubdocMultiPathFailure         Status = 0x00cc // Multi-path failure
	StatusSubdocSuccessDeleted           Status = 0x00cd // Success on deleted document
	StatusSubdocXattrInvalidFlagCombo    Status = 0x00ce // Invalid XATTR flag combo
	StatusSubdocXattrInvalidKeyCombo     Status = 0x00cf // Invalid XATTR key combo
	StatusSubdocXattrUnknownMacro        Status = 0x00d0 // Unknown XATTR macro
	StatusSubdocXattrUnknownVattr        Status = 0x00d1 // Unknown XATTR virtual attribute
	StatusSubdocXattrCantModifyVattr     Status = 0x00d2 // Can't modify virtual attribute
	StatusSubdocMultiPathFailureDeleted  Status = 0x00d3 // Multi-path failure on deleted doc
	StatusSubdocInvalidXattrOrder        Status = 0x00d4 // Invalid XATTR order
	StatusSubdocXattrUnknownVattrMacro   Status = 0x00d5 // Unknown virtual attribute macro
	StatusSubdocCanOnlyReviveDeletedDocs Status = 0x00d6 // Can only revive deleted documents
	StatusSubdocDeletedDocCantHaveValue  Status = 0x00d7 // Deleted doc can't have value
	StatusSubdocFieldNotBinaryValue      Status = 0x00d8 // Field is not binary value
)

func (s Status) String() string {
	switch s {
	case StatusSuccess:
		return "Success"

	// Key/value errors
	case StatusKeyNotFound:
		return "KeyNotFound"
	case StatusKeyExists:
		return "KeyExists"
	case StatusValueTooLarge:
		return "ValueTooLarge"
	case StatusInvalidArguments:
		return "InvalidArguments"
	case StatusItemNotStored:
		return "ItemNotStored"
	case StatusNonNumeric:
		return "NonNumeric"
	case StatusVBucketNotHere:
		return "VBucketNotHere"
	case StatusNoBucket:
		return "NoBucket"
	case StatusLocked:
		return "Locked"
	case StatusDcpStreamNotFound:
		return "DcpStreamNotFound"
	case StatusOpaqueNoMatch:
		return "OpaqueNoMatch"
	case StatusEWouldThrottle:
		return "EWouldThrottle"
	case StatusEConfigOnly:
		return "EConfigOnly"
	case StatusNotLocked:
		return "NotLocked"
	case StatusCasValueInvalid:
		return "CasValueInvalid"

	// Authentication errors
	case StatusAuthStale:
		return "AuthStale"
	case StatusAuthError:
		return "AuthError"
	case StatusAuthContinue:
		return "AuthContinue"
	case StatusOutOfRange:
		return "OutOfRange"
	case StatusRollback:
		return "Rollback"
	case StatusNoAccess:
		return "NoAccess"
	case StatusNotInitialized:
		return "NotInitialized"
	case StatusEncryptionKeyNotAvailable:
		return "EncryptionKeyNotAvailable"
	case StatusChecksumMismatch:
		return "ChecksumMismatch"

	// Rate limiting errors
	case StatusRateLimitedNetworkIngress:
		return "RateLimitedNetworkIngress"
	case StatusRateLimitedNetworkEgress:
		return "RateLimitedNetworkEgress"
	case StatusRateLimitedMaxConnections:
		return "RateLimitedMaxConnections"
	case StatusRateLimitedMaxCommands:
		return "RateLimitedMaxCommands"
	case StatusBucketSizeLimitExceeded:
		return "BucketSizeLimitExceeded"
	case StatusBucketResidentRatioTooLow:
		return "BucketResidentRatioTooLow"
	case StatusBucketDataSizeTooBig:
		return "BucketDataSizeTooBig"
	case StatusBucketDiskSpaceTooLow:
		return "BucketDiskSpaceTooLow"

	// Bucket state errors
	case StatusBucketPaused:
		return "BucketPaused"
	case StatusCancelled:
		return "Cancelled"

	// General errors
	case StatusUnknownFrameInfo:
		return "UnknownFrameInfo"
	case StatusUnknownCommand:
		return "UnknownCommand"
	case StatusOutOfMemory:
		return "OutOfMemory"
	case StatusNotSupported:
		return "NotSupported"
	case StatusInternalError:
		return "InternalError"
	case StatusBusy:
		return "Busy"
	case StatusTemporaryFailure:
		return "TemporaryFailure"
	case StatusXattrInvalid:
		return "XattrInvalid"

	// Collection errors
	case StatusUnknownCollection:
		return "UnknownCollection"
	case StatusCannotApplyCollectionsManifest:
		return "CannotApplyCollectionsManifest"
	case StatusUnknownScope:
		return "UnknownScope"
	case StatusDcpStreamIDInvalid:
		return "DcpStreamIdInvalid"

	// Durability errors
	case StatusDurabilityInvalidLevel:
		return "DurabilityInvalidLevel"
	case StatusDurabilityImpossible:
		return "DurabilityImpossible"
	case StatusSyncWriteInProgress:
		return "SyncWriteInProgress"
	case StatusSyncWriteAmbiguous:
		return "SyncWriteAmbiguous"
	case StatusSyncWriteReCommitInProgress:
		return "SyncWriteReCommitInProgress"

	// Range scan status
	case StatusRangeScanCancelled:
		return "RangeScanCancelled"
	case StatusRangeScanMore:
		return "RangeScanMore"
	case StatusRangeScanComplete:
		return "RangeScanComplete"
	case StatusVbUUIDNotEqual:
		return "VbUuidNotEqual"

	// Sub-document errors
	case StatusSubdocPathNotFound:
		return "SubdocPathNotFound"
	case StatusSubdocPathMismatch:
		return "SubdocPathMismatch"
	case StatusSubdocPathInvalid:
		return "SubdocPathInvalid"
	case StatusSubdocPathTooBig:
		return "SubdocPathTooBig"
	case StatusSubdocDocTooDeep:
		return "SubdocDocTooDeep"
	case StatusSubdocValueCantInsert:
		return "SubdocValueCantInsert"
	case StatusSubdocDocNotJSON:
		return "SubdocDocNotJson"
	case StatusSubdocNumOutOfRange:
		return "SubdocNumOutOfRange"
	case StatusSubdocDeltaInvalid:
		return "SubdocDeltaInvalid"
	case StatusSubdocPathExists:
		return "SubdocPathExists"
	case StatusSubdocValueTooDeep:
		return "SubdocValueTooDeep"
	case StatusSubdocInvalidCombo:
		return "SubdocInvalidCombo"
	case StatusSubdocMultiPathFailure:
		return "SubdocMultiPathFailure"
	case StatusSubdocSuccessDeleted:
		return "SubdocSuccessDeleted"
	case StatusSubdocXattrInvalidFlagCombo:
		return "SubdocXattrInvalidFlagCombo"
	case StatusSubdocXattrInvalidKeyCombo:
		return "SubdocXattrInvalidKeyCombo"
	case StatusSubdocXattrUnknownMacro:
		return "SubdocXattrUnknownMacro"
	case StatusSubdocXattrUnknownVattr:
		return "SubdocXattrUnknownVattr"
	case StatusSubdocXattrCantModifyVattr:
		return "SubdocXattrCantModifyVattr"
	case StatusSubdocMultiPathFailureDeleted:
		return "SubdocMultiPathFailureDeleted"
	case StatusSubdocInvalidXattrOrder:
		return "SubdocInvalidXattrOrder"
	case StatusSubdocXattrUnknownVattrMacro:
		return "SubdocXattrUnknownVattrMacro"
	case StatusSubdocCanOnlyReviveDeletedDocs:
		return "SubdocCanOnlyReviveDeletedDocs"
	case StatusSubdocDeletedDocCantHaveValue:
		return "SubdocDeletedDocCantHaveValue"
	case StatusSubdocFieldNotBinaryValue:
		return "SubdocFieldNotBinaryValue"

	default:
		return "Unknown"
	}
}

// IsSuccess returns true if this status indicates success.
func (s Status) IsSuccess() bool {
	return s == StatusSuccess
}

// IsError returns true if this status indicates an error.
func (s Status) IsError() bool {
	return s != StatusSuccess && s != StatusAuthContinue
}

// DataType is a bitfield describing the value format
type DataType uint8

const (
	DataTypeRaw    DataType = 0x00
	DataTypeJSON   DataType = 0x01
	DataTypeSnappy DataType = 0x02 // Snappy compressed
	DataTypeXattr  DataType = 0x04 // Extended attributes present
)

// HasJSON returns true if the data is JSON formatted.
func (d DataType) HasJSON() bool {
	return d&DataTypeJSON != 0
}

// HasSnappy returns true if the data is Snappy compressed.
func (d DataType) HasSnappy() bool {
	return d&DataTypeSnappy != 0
}

// HasXattr returns true if extended attributes are present.
func (d DataType) HasXattr() bool {
	return d&DataTypeXattr != 0
}
