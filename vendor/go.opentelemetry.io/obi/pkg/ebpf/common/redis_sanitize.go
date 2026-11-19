// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"strconv"
	"strings"
)

const redisSanitizedArg = "?"

type redisArgPolicy uint8

const (
	// redisMaskAfterPrefix keeps the first keep arguments and masks the rest.
	redisMaskAfterPrefix redisArgPolicy = iota
	// redisKeepAllArgs keeps every argument: keys, cursors, ranges and options.
	redisKeepAllArgs
	// redisMaskPairValues keeps the first keep arguments, then alternates
	// between keeping a key or field name and masking its value.
	redisMaskPairValues
	// redisEvalArgs keeps the script, numkeys and the declared keys, and masks
	// the script arguments.
	redisEvalArgs
	// redisStreamEntryArgs keeps the key, the trimming options and the entry ID,
	// then masks each field value.
	redisStreamEntryArgs
)

type redisArgRule struct {
	policy redisArgPolicy
	keep   int
}

// The command table follows the OpenTelemetry Java instrumentation's Redis
// command sanitizer, except that SPUBLISH masks its message like PUBLISH and
// XADD finds the entry ID after any trimming options.
var redisArgRules = func() map[string]redisArgRule {
	rules := map[string]redisArgRule{}
	add := func(rule redisArgRule, ops ...string) {
		for _, op := range ops {
			rules[op] = rule
		}
	}

	add(redisArgRule{policy: redisKeepAllArgs},
		// cluster
		"CLUSTER", "FAILOVER", "READONLY", "READWRITE",
		// connection
		"CLIENT", "ECHO", "PING", "QUIT", "RESET", "SELECT",
		// geo
		"GEOADD", "GEODIST", "GEOHASH", "GEOPOS", "GEORADIUS", "GEORADIUS_RO",
		"GEORADIUSBYMEMBER", "GEORADIUSBYMEMBER_RO", "GEOSEARCH", "GEOSEARCHSTORE",
		// hashes
		"HDEL", "HEXISTS", "HGET", "HGETALL", "HINCRBY", "HINCRBYFLOAT", "HKEYS", "HLEN",
		"HMGET", "HRANDFIELD", "HSCAN", "HSTRLEN", "HVALS",
		// hyperloglog
		"PFCOUNT", "PFMERGE",
		// keys
		"COPY", "DEL", "DUMP", "EXISTS", "EXPIRE", "EXPIREAT", "EXPIRETIME", "KEYS", "MOVE",
		"OBJECT", "PERSIST", "PEXPIRE", "PEXPIREAT", "PEXPIRETIME", "PTTL", "RANDOMKEY",
		"RENAME", "RENAMENX", "SCAN", "SORT", "SORT_RO", "TOUCH", "TTL", "TYPE", "UNLINK", "WAIT",
		// lists
		"BLMOVE", "BLMPOP", "BLPOP", "BRPOP", "BRPOPLPUSH", "LINDEX", "LLEN", "LMOVE", "LMPOP",
		"LPOP", "LRANGE", "LTRIM", "RPOP", "RPOPLPUSH",
		// pub/sub
		"PSUBSCRIBE", "PUBSUB", "PUNSUBSCRIBE", "SSUBSCRIBE", "SUBSCRIBE",
		"SUNSUBSCRIBE", "UNSUBSCRIBE",
		// scripting
		"SCRIPT",
		// server
		"BGREWRITEAOF", "BGSAVE", "COMMAND", "DBSIZE", "DEBUG", "FLUSHALL", "FLUSHDB", "INFO",
		"LASTSAVE", "LATENCY", "LOLWUT", "MEMORY", "MODULE", "MONITOR", "PSYNC", "REPLICAOF",
		"ROLE", "SAVE", "SHUTDOWN", "SLAVEOF", "SLOWLOG", "SWAPDB", "SYNC", "TIME",
		// sets
		"SCARD", "SDIFF", "SDIFFSTORE", "SINTER", "SINTERCARD", "SINTERSTORE", "SMEMBERS",
		"SPOP", "SRANDMEMBER", "SSCAN", "SUNION", "SUNIONSTORE",
		// sorted sets
		"BZMPOP", "BZPOPMAX", "BZPOPMIN", "ZCARD", "ZDIFF", "ZDIFFSTORE", "ZINTER",
		"ZINTERCARD", "ZINTERSTORE", "ZMPOP", "ZPOPMAX", "ZPOPMIN", "ZRANDMEMBER", "ZRANGE",
		"ZRANGESTORE", "ZREMRANGEBYRANK", "ZREVRANGE", "ZSCAN", "ZUNION", "ZUNIONSTORE",
		// streams
		"XACK", "XAUTOCLAIM", "XCLAIM", "XDEL", "XGROUP", "XINFO", "XLEN", "XPENDING",
		"XRANGE", "XREAD", "XREADGROUP", "XREVRANGE", "XTRIM",
		// strings
		"BITCOUNT", "BITFIELD", "BITFIELD_RO", "BITOP", "BITPOS", "DECR", "DECRBY", "GET",
		"GETBIT", "GETDEL", "GETEX", "GETRANGE", "INCR", "INCRBY", "INCRBYFLOAT", "LCS",
		"MGET", "SETBIT", "STRALGO", "STRLEN",
		// transactions
		"DISCARD", "EXEC", "MULTI", "UNWATCH", "WATCH",
	)

	add(redisArgRule{policy: redisMaskAfterPrefix, keep: 1},
		"PFADD", "LPOS", "LPUSH", "LPUSHX", "LREM", "LSET", "RPUSH", "RPUSHX", "PUBLISH",
		"SADD", "SPUBLISH", "SISMEMBER", "SMISMEMBER", "SREM", "ZADD", "ZCOUNT", "ZINCRBY", "ZLEXCOUNT",
		"ZMSCORE", "ZRANGEBYLEX", "ZRANGEBYSCORE", "ZRANK", "ZREM", "ZREMRANGEBYLEX",
		"ZREMRANGEBYSCORE", "ZREVRANGEBYLEX", "ZREVRANGEBYSCORE", "ZREVRANK", "ZSCORE",
		"ACL", "APPEND", "GETSET", "SET", "SETNX", "SETRANGE",
	)
	add(redisArgRule{policy: redisMaskAfterPrefix, keep: 2},
		"HELLO", "HSETNX", "RESTORE", "LINSERT", "PSETEX", "SETEX", "SMOVE", "CONFIG",
	)
	add(redisArgRule{policy: redisMaskAfterPrefix, keep: 6}, "MIGRATE")

	add(redisArgRule{policy: redisMaskPairValues}, "MSET", "MSETNX")
	add(redisArgRule{policy: redisMaskPairValues, keep: 1}, "HMSET", "HSET")
	add(redisArgRule{policy: redisStreamEntryArgs}, "XADD")

	add(redisArgRule{policy: redisEvalArgs}, "EVAL", "EVAL_RO", "EVALSHA", "EVALSHA_RO")

	return rules
}()

// sanitizeRedisCommand renders a command with its argument values replaced by
// "?". Commands missing from the table, AUTH included, have every argument
// replaced.
func sanitizeRedisCommand(op string, args [][]byte) string {
	rule := redisArgRules[strings.ToUpper(op)]

	var b strings.Builder
	b.WriteString(op)
	for i, arg := range args {
		b.WriteByte(' ')
		if keepRedisArg(rule, args, i) {
			b.Write(arg)
		} else {
			b.WriteString(redisSanitizedArg)
		}
	}
	return b.String()
}

func keepRedisArg(rule redisArgRule, args [][]byte, i int) bool {
	switch rule.policy {
	case redisKeepAllArgs:
		return true
	case redisMaskPairValues:
		return i < rule.keep || (i-rule.keep)%2 == 0
	case redisEvalArgs:
		return i < redisEvalKeptArgs(args)
	case redisStreamEntryArgs:
		idIndex := redisStreamEntryIDIndex(args)
		return i <= idIndex || (i-idIndex)%2 == 1
	default:
		return i < rule.keep
	}
}

// redisEvalKeptArgs counts the script, numkeys and the declared keys.
func redisEvalKeptArgs(args [][]byte) int {
	const scriptAndNumKeys = 2
	if len(args) < scriptAndNumKeys {
		return len(args)
	}
	numKeys, err := strconv.Atoi(string(args[1]))
	if err != nil || numKeys < 0 {
		return scriptAndNumKeys
	}
	return scriptAndNumKeys + min(numKeys, len(args)-scriptAndNumKeys)
}

// redisStreamEntryIDIndex skips the key and the XADD options
// [NOMKSTREAM] [MAXLEN|MINID [=|~] threshold [LIMIT count]] to find the entry ID.
func redisStreamEntryIDIndex(args [][]byte) int {
	i := 1
	for i < len(args) {
		switch strings.ToUpper(string(args[i])) {
		case "NOMKSTREAM":
			i++
		case "MAXLEN", "MINID":
			i++
			if i < len(args) && (string(args[i]) == "=" || string(args[i]) == "~") {
				i++
			}
			i++
			if i < len(args) && strings.EqualFold(string(args[i]), "LIMIT") {
				i += 2
			}
		default:
			return i
		}
	}
	return i
}
