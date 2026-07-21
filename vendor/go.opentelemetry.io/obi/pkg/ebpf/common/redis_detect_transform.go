// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"strconv"
	"strings"
	"unsafe"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	trace2 "go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

const (
	minRedisFrameLen = 3
	redisDelim       = "\r\n"
)

var redisDelimBytes = []byte(redisDelim)

var redisErrors = [...]struct {
	prefix []byte
	code   string
}{
	{[]byte("ERR "), "ERR"},
	{[]byte("WRONGTYPE "), "WRONGTYPE"},
	{[]byte("MOVED "), "MOVED"},
	{[]byte("ASK "), "ASK"},
	{[]byte("BUSY "), "BUSY"},
	{[]byte("NOSCRIPT "), "NOSCRIPT"},
	{[]byte("CLUSTERDOWN "), "CLUSTERDOWN"},
	{[]byte("READONLY "), "READONLY"},
}

// core command words per https://github.com/redis/redis/tree/unstable/src/commands;
// only a tie-break for reversal detection, so completeness is not required
var redisKnownOps = func() map[string]struct{} {
	ops := map[string]struct{}{}
	for _, op := range []string{
		"ACL", "APPEND", "AUTH", "BGREWRITEAOF", "BGSAVE", "BITCOUNT", "BITFIELD", "BITOP", "BITPOS",
		"BLMOVE", "BLMPOP", "BLPOP", "BRPOP", "BRPOPLPUSH", "BZMPOP", "BZPOPMAX", "BZPOPMIN",
		"CLIENT", "CLUSTER", "COMMAND", "CONFIG", "COPY", "DBSIZE", "DEBUG", "DECR", "DECRBY",
		"DEL", "DISCARD", "DUMP", "ECHO", "EVAL", "EVALSHA", "EVALSHA_RO", "EVAL_RO", "EXEC",
		"EXISTS", "EXPIRE", "EXPIREAT", "EXPIRETIME", "FAILOVER", "FCALL", "FCALL_RO", "FLUSHALL",
		"FLUSHDB", "FUNCTION", "GEOADD", "GEODIST", "GEOHASH", "GEOPOS", "GEOSEARCH",
		"GEOSEARCHSTORE", "GET", "GETDEL", "GETEX", "GETRANGE", "GETSET", "HDEL", "HELLO",
		"HEXISTS", "HEXPIRE", "HGET", "HGETALL", "HGETDEL", "HGETEX", "HINCRBY", "HINCRBYFLOAT",
		"HKEYS", "HLEN", "HMGET", "HMSET", "HPERSIST", "HRANDFIELD", "HSCAN", "HSET", "HSETNX",
		"HSTRLEN", "HTTL", "HVALS", "INCR", "INCRBY", "INCRBYFLOAT", "INFO", "KEYS", "LASTSAVE",
		"LATENCY", "LCS", "LINDEX", "LINSERT", "LLEN", "LMOVE", "LMPOP", "LOLWUT", "LPOP", "LPOS",
		"LPUSH", "LPUSHX", "LRANGE", "LREM", "LSET", "LTRIM", "MEMORY", "MGET", "MIGRATE",
		"MONITOR", "MOVE", "MSET", "MSETNX", "MULTI", "OBJECT", "PERSIST", "PEXPIRE", "PEXPIREAT",
		"PEXPIRETIME", "PFADD", "PFCOUNT", "PFMERGE", "PING", "PSETEX", "PSUBSCRIBE", "PSYNC",
		"PTTL", "PUBLISH", "PUBSUB", "PUNSUBSCRIBE", "QUIT", "RANDOMKEY", "RENAME", "RENAMENX",
		"REPLICAOF", "RESET", "RESTORE", "ROLE", "RPOP", "RPOPLPUSH", "RPUSH", "RPUSHX", "SADD",
		"SAVE", "SCAN", "SCARD", "SCRIPT", "SDIFF", "SDIFFSTORE", "SELECT", "SET", "SETEX",
		"SETNX", "SETRANGE", "SHUTDOWN", "SINTER", "SINTERCARD", "SINTERSTORE", "SISMEMBER",
		"SLAVEOF", "SLOWLOG", "SMEMBERS", "SMISMEMBER", "SMOVE", "SORT", "SORT_RO", "SPOP",
		"SRANDMEMBER", "SREM", "SSCAN", "STRLEN", "SUBSCRIBE", "SUNION", "SUNIONSTORE", "SWAPDB",
		"SYNC", "TIME", "TOUCH", "TTL", "TYPE", "UNLINK", "UNSUBSCRIBE", "UNWATCH", "WAIT",
		"WAITAOF", "WATCH", "XACK", "XADD", "XAUTOCLAIM", "XCLAIM", "XDEL", "XGROUP", "XINFO",
		"XLEN", "XPENDING", "XRANGE", "XREAD", "XREADGROUP", "XREVRANGE", "XSETID", "XTRIM",
		"ZADD", "ZCARD", "ZCOUNT", "ZDIFF", "ZDIFFSTORE", "ZINCRBY", "ZINTER", "ZINTERCARD",
		"ZINTERSTORE", "ZLEXCOUNT", "ZMPOP", "ZMSCORE", "ZPOPMAX", "ZPOPMIN", "ZRANDMEMBER",
		"ZRANGE", "ZRANGEBYLEX", "ZRANGEBYSCORE", "ZRANGESTORE", "ZRANK", "ZREM",
		"ZREMRANGEBYLEX", "ZREMRANGEBYRANK", "ZREMRANGEBYSCORE", "ZREVRANGE", "ZREVRANGEBYLEX",
		"ZREVRANGEBYSCORE", "ZREVRANK", "ZSCAN", "ZSCORE", "ZUNION", "ZUNIONSTORE",
	} {
		ops[op] = struct{}{}
	}
	return ops
}()

func isKnownRedisOp(op string) bool {
	_, ok := redisKnownOps[strings.ToUpper(op)]
	return ok
}

func isRedis(buf *largebuf.LargeBuffer) bool {
	if buf.Len() < minRedisFrameLen {
		return false
	}
	return isRedisOp(buf.UnsafeView())
}

//nolint:cyclop
func isRedisOp(buf []uint8) bool {
	if len(buf) == 0 {
		return false
	}
	c := buf[0]

	switch c {
	case '+':
		return crlfTerminatedMatch(buf[1:], func(c uint8) bool {
			return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '.' || c == ' ' || c == '-' || c == '_'
		})
	case '-':
		_, isError := getRedisError(buf[1:])
		return isError
	case ':', '$', '*', '(', '!', '=', '%', '~', '>', '|':
		return crlfTerminatedMatch(buf[1:], func(c uint8) bool {
			return (c >= '0' && c <= '9') || c == '-'
		})
	case '#':
		return len(buf) >= 4 && (buf[1] == 't' || buf[1] == 'f') && buf[2] == '\r' && buf[3] == '\n'
	case '_':
		return len(buf) >= 3 && buf[1] == '\r' && buf[2] == '\n'
	case ',':
		// RESP3 double: numbers plus inf/nan and exponent notation
		return crlfTerminatedMatch(buf[1:], func(c uint8) bool {
			return (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' ||
				c == 'e' || c == 'E' || c == 'i' || c == 'n' || c == 'f' || c == 'a'
		})
	}

	return false
}

func getRedisError(buf []uint8) (request.DBError, bool) {
	description := string(bytes.Trim(buf, "\r\n"))
	errorCode := ""

	for _, e := range redisErrors {
		if bytes.HasPrefix(buf, e.prefix) {
			errorCode = e.code
			break
		}
	}
	dbError := request.DBError{
		Description: description,
		ErrorCode:   errorCode,
	}
	return dbError, errorCode != ""
}

func crlfTerminatedMatch(buf []uint8, matches func(c uint8) bool) bool {
	cr := false
	i := 0
	for ; i < len(buf); i++ {
		c := buf[i]
		if matches(c) {
			continue
		}
		if c == '\r' {
			cr = true
			break
		}

		return false
	}

	if !cr || i >= len(buf)-1 {
		return false
	}

	return buf[i+1] == '\n'
}

type redisCommand struct {
	op   string
	text string
}

type redisReply struct {
	status  int
	dbError request.DBError
}

// readRESPLine returns the bytes before the next CRLF and the offset just past it
func readRESPLine(buf []byte, pos int) ([]byte, int, bool) {
	rel := bytes.Index(buf[pos:], redisDelimBytes)
	if rel < 0 {
		return nil, 0, false
	}
	return buf[pos : pos+rel], pos + rel + len(redisDelimBytes), true
}

func parseRESPInt(line []byte) (int, bool) {
	if len(line) == 0 {
		return 0, false
	}
	i := 0
	neg := false
	if line[0] == '-' {
		neg = true
		i = 1
	}
	if i >= len(line) {
		return 0, false
	}
	n := 0
	for ; i < len(line); i++ {
		c := line[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return 0, false
		}
	}
	if neg {
		n = -n
	}
	return n, true
}

// letters plus '.', '_', '-' (JSON.SET, EVALSHA_RO, RESTORE-ASKING); reply payload tokens rarely fit
func isRedisCommandToken(tok []byte) bool {
	if len(tok) == 0 {
		return false
	}
	for _, c := range tok {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func isPrintableToken(tok []byte) bool {
	for _, c := range tok {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

func salvageRedisCommand(op string, text *strings.Builder) *redisCommand {
	if op == "" {
		return nil
	}
	return &redisCommand{op: op, text: text.String()}
}

// parseRedisCommand reads one RESP array at pos, honoring bulk lengths so binary
// values can't derail the scan; on truncation it salvages the complete tokens and returns ok=false
//
//nolint:cyclop
func parseRedisCommand(buf []byte, pos int) (*redisCommand, int, bool) {
	header, next, ok := readRESPLine(buf, pos)
	if !ok || len(header) < 2 || header[0] != '*' {
		return nil, 0, false
	}
	n, ok := parseRESPInt(header[1:])
	if !ok || n <= 0 {
		// *-1 and *0 are reply shapes, not commands
		return nil, 0, false
	}

	op := ""
	textDone := false
	var text strings.Builder
	pos = next

	for i := 0; i < n; i++ {
		lenLine, tokStart, ok := readRESPLine(buf, pos)
		if !ok || len(lenLine) < 2 || lenLine[0] != '$' {
			return salvageRedisCommand(op, &text), 0, false
		}
		l, ok := parseRESPInt(lenLine[1:])
		if !ok || l < 0 {
			return salvageRedisCommand(op, &text), 0, false
		}
		tokEnd := tokStart + l
		if tokEnd+len(redisDelimBytes) > len(buf) ||
			!bytes.Equal(buf[tokEnd:tokEnd+len(redisDelimBytes)], redisDelimBytes) {
			return salvageRedisCommand(op, &text), 0, false
		}
		tok := buf[tokStart:tokEnd]
		if i == 0 {
			if !isRedisCommandToken(tok) {
				return nil, 0, false
			}
			op = string(tok)
			text.Write(tok)
		} else if !textDone {
			if isPrintableToken(tok) {
				text.WriteByte(' ')
				text.Write(tok)
			} else {
				textDone = true
			}
		}
		pos = tokEnd + len(redisDelimBytes)
	}

	return &redisCommand{op: op, text: text.String()}, pos, true
}

// parseRedisCommands splits a buffer into its pipelined commands; nil means
// the buffer isn't a command stream (how replies are told apart from commands)
func parseRedisCommands(buf []byte) []redisCommand {
	var cmds []redisCommand
	pos := 0
	for pos < len(buf) && buf[pos] == '*' {
		cmd, next, ok := parseRedisCommand(buf, pos)
		if cmd != nil {
			cmds = append(cmds, *cmd)
		}
		if !ok {
			break
		}
		pos = next
	}
	return cmds
}

const maxRESPDepth = 8

// skipRESPValue advances past one RESP value of any type, including RESP3 frames
//
//nolint:cyclop
func skipRESPValue(buf []byte, pos, depth int) (int, bool) {
	if depth > maxRESPDepth || pos >= len(buf) {
		return 0, false
	}
	t := buf[pos]
	line, next, ok := readRESPLine(buf, pos)
	if !ok {
		return 0, false
	}
	switch t {
	case '+', '-', ':', ',', '(', '#', '_':
		return next, true
	case '$', '=', '!':
		l, ok := parseRESPInt(line[1:])
		if !ok {
			return 0, false
		}
		if l < 0 {
			return next, true
		}
		end := next + l + len(redisDelimBytes)
		if end > len(buf) {
			return 0, false
		}
		return end, true
	case '*', '~', '>', '%', '|':
		n, ok := parseRESPInt(line[1:])
		if !ok {
			return 0, false
		}
		if n < 0 {
			return next, true
		}
		if t == '%' || t == '|' {
			n *= 2
		}
		for i := 0; i < n; i++ {
			next, ok = skipRESPValue(buf, next, depth+1)
			if !ok {
				return 0, false
			}
		}
		return next, true
	}
	return 0, false
}

// parseRedisReplies splits the response stream into per-command results; RESP3
// push frames aren't positional replies and attributes decorate the next value,
// so both are skipped
func parseRedisReplies(buf []byte, maxReplies int) []redisReply {
	replies := make([]redisReply, 0, min(maxReplies, 8))
	pos := 0
	for pos < len(buf) && len(replies) < maxReplies {
		t := buf[pos]
		next, ok := skipRESPValue(buf, pos, 0)
		if !ok {
			break
		}
		if t != '>' && t != '|' {
			r := redisReply{}
			switch t {
			case '-':
				line, _, _ := readRESPLine(buf, pos)
				dbError, known := getRedisError(line[1:])
				r.dbError = dbError
				if known {
					r.status = 1
				}
			case '!':
				// RESP3 bulk error: text is on the line after the length header
				if _, tstart, ok := readRESPLine(buf, pos); ok {
					if line, _, ok := readRESPLine(buf, tstart); ok {
						dbError, known := getRedisError(line)
						r.dbError = dbError
						if known {
							r.status = 1
						}
					}
				}
			}
			replies = append(replies, r)
		}
		pos = next
	}
	return replies
}

func getRedisDB(connInfo BpfConnectionInfoT, op, text string, dbCache *simplelru.LRU[BpfConnectionInfoT, int]) (int, bool) {
	if dbCache == nil {
		return -1, false
	}
	db, found := dbCache.Get(connInfo)
	switch {
	case strings.EqualFold(op, "SELECT"):
		// get db number from text after first space
		if text != "" {
			parts := strings.Split(text, " ")
			if len(parts) > 1 {
				if dbNum, err := strconv.Atoi(parts[1]); err == nil && dbNum >= 0 {
					dbCache.Add(connInfo, dbNum)
				}
			}
		}
	case strings.EqualFold(op, "QUIT"):
		dbCache.Remove(connInfo)
	}
	return db, found
}

func TCPToRedisToSpan(trace *TCPRequestInfo, op, text string, status, db int, dbError request.DBError) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0
	dbNamespace := ""
	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	reqType := request.EventTypeRedisClient
	if trace.Direction == 0 {
		reqType = request.EventTypeRedisServer
	}

	if db >= 0 {
		// If we have a valid db number, we can use it as a namespace
		dbNamespace = strconv.Itoa(db)
	}

	return request.Span{
		Type:          reqType,
		Method:        op,
		Path:          text,
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
			HostPID:   app.PID(trace.Pid.HostPid),
			UserPID:   app.PID(trace.Pid.UserPid),
			Namespace: trace.Pid.Ns,
		},
		DBError:     dbError,
		DBNamespace: dbNamespace,
	}
}

func ReadGoRedisRequestIntoSpan(parseCtx *EBPFParseContext, record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ReinterpretCast[GoRedisClientInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	cmds := parseRedisCommands(event.Buf[:min(int(event.BufLen), len(event.Buf))])
	if len(cmds) == 0 {
		// We know it's redis request here, it just didn't complete correctly
		event.Err = 1
		return goRedisSpan(event, "", ""), false, nil
	}

	spans := make([]request.Span, 0, len(cmds))
	for i := range cmds {
		spans = append(spans, goRedisSpan(event, cmds[i].op, cmds[i].text))
	}
	if len(spans) > 1 {
		// clear SpanID on extras so tracesgen assigns fresh IDs
		for i := 1; i < len(spans); i++ {
			spans[i].SpanID = trace2.SpanID{}
		}
		parseCtx.emitExtraSpans(spans[1:]...)
	}
	return spans[0], false, nil
}

func goRedisSpan(event *GoRedisClientInfo, op, text string) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if event.Conn.S_port != 0 || event.Conn.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&event.Conn)).reqHostInfo()
		hostPort = int(event.Conn.D_port)
	}

	return request.Span{
		Type:          request.EventTypeRedisClient, // always client for Go
		Method:        op,
		Path:          text,
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
			HostPID:   app.PID(event.Pid.HostPid),
			UserPID:   app.PID(event.Pid.UserPid),
			Namespace: event.Pid.Ns,
		},
	}
}
