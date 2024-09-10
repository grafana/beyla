package svc

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"hash/fnv"
)

var encoding = base32.NewEncoding("0123456789abcdefghijklmnopqrstuv").WithPadding('w')

// UID uniquely identifies a service instance.
// When built through the Append function, it will contain a FNV64 hash string in Base32
type UID string

// NewUID creates a UID containing the argument hash as a Base32 string
func NewUID(fromString string) UID {
	return UID("").Append(fromString)
}

// Append returns a UID whose contents are the hash concatenating the current UID value
// (which is already a hash) with the passed string
func (u UID) Append(str string) UID {
	return u.append([]byte(str))
}

// AppendUint32 returns a UID whose contents are the hash concatenating the current UID value
// (which is already a hash) with the bytes of the passed integer
func (u UID) AppendUint32(i uint32) UID {
	return u.append(binary.LittleEndian.AppendUint32(nil, i))
}

func (u UID) append(content []byte) UID {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(u))
	_, _ = hasher.Write(content)
	buf := bytes.Buffer{}

	encoder := base32.NewEncoder(encoding, &buf)
	_, _ = encoder.Write(hasher.Sum(nil))

	return UID(buf.String())
}
