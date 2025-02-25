// helper to lookup an entry in /etc/ld.so.cache - only the 'new' format is
// supported

package addrinfo

import (
	"fmt"
	"math"
	"unsafe"
)

const kMagic = "glibc-ld.so.cache"
const kVersion = "1.1"

// this is the file header, the naming cacheFileNew is analogous to the glibc
// cache_file_new struct
type cacheFileNew struct {
	Magic        [len(kMagic)]byte
	Version      [len(kVersion)]byte
	NLibs        uint32
	LenStrings   uint32
	Flags        uint8
	_            [3]byte
	ExtensionOff uint32
	_            [3]uint32
}

const kHeaderSize = int(unsafe.Sizeof(cacheFileNew{}))

// akin to file_entry_new in glibc
type fileEntryNew struct {
	Flags           int32
	Key             uint32
	Value           uint32
	OSVersionUnused uint32
	Hwcap           uint64
}

const kEntrySize = int(unsafe.Sizeof(fileEntryNew{}))

func ldCacheFind(lib string) (string, error) {
	mappedFile, err := mapFile("/etc/ld.so.cache")

	if err != nil {
		return "", err
	}

	defer mappedFile.Close()

	data := mappedFile.data

	if len(data) < kHeaderSize {
		return "", fmt.Errorf("/etc/ld.so.cache appears to be corrupt")
	}

	if len(data) > math.MaxUint32 {
		return "", fmt.Errorf("/etc/ld.so.cache is too big")
	}

	hdr := (*cacheFileNew)(unsafe.Pointer(&data[0]))

	if string(hdr.Magic[:]) != kMagic {
		return "", fmt.Errorf("invalid magic number: %s", hdr.Magic)
	}

	if string(hdr.Version[:]) != kVersion {
		return "", fmt.Errorf("unsupported version: %s", hdr.Version)
	}

	if uintptr(hdr.NLibs) > math.MaxInt {
		return "", fmt.Errorf("/etc/ld.so.cache is too big")
	}

	libs := data[kHeaderSize:]
	nLibs := int(hdr.NLibs)

	if len(libs) < nLibs*kEntrySize {
		return "", fmt.Errorf("/etc/ld.so.cache missing library entries")
	}

	dataLen := uint32(len(data))

	for i := 0; i < nLibs; i++ {
		entry := (*fileEntryNew)(unsafe.Pointer(&libs[i*kEntrySize]))

		if entry.Key > dataLen || entry.Value > dataLen {
			continue
		}

		key := stringView(data[entry.Key:])

		if string(key) == lib {
			value := stringView(data[entry.Value:])
			return string(value), nil
		}
	}

	return "", nil
}

func stringView(s []byte) []byte {
	for i, c := range s {
		if c == 0 {
			return s[:i]
		}
	}

	return []byte{}
}
