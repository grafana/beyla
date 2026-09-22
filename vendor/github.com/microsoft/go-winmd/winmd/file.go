// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
)

// heap provides access to metadata heaps as defined in §II.24.2.
type heap struct {
	// Embed ReaderAt for ReadAt method.
	// Do not embed SectionReader directly
	// to avoid having Read and Seek.
	// If a client wants Read and Seek it must use
	// Open() to avoid fighting over the seek offset
	// with other clients.
	io.ReaderAt
	Size uint32
	sr   *io.SectionReader
	name string
}

// Data reads and returns the contents of the heap h.
func (h *heap) Data() ([]byte, error) {
	return readData(h.Open(), uint64(h.Size))
}

// Open returns a new ReadSeeker reading the heap h.
func (s *heap) Open() io.ReadSeeker {
	return io.NewSectionReader(s.sr, 0, 1<<63-1)
}

func newMetadata(pefile *pe.File) (*Metadata, error) {
	if pefile.OptionalHeader == nil {
		return nil, errors.New("pe optional header is required to parse as winmd, but it is missing")
	}

	_, pe64 := pefile.OptionalHeader.(*pe.OptionalHeader64)

	// grab the number of data directory entries.
	var ddLength uint32
	if pe64 {
		ddLength = pefile.OptionalHeader.(*pe.OptionalHeader64).NumberOfRvaAndSizes
	} else {
		ddLength = pefile.OptionalHeader.(*pe.OptionalHeader32).NumberOfRvaAndSizes
	}

	// check that the length of data directory entries is large
	// enough to include the COM descriptor directory.
	if ddLength < pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR+1 {
		return nil, fmt.Errorf("data directory entries length (%d) is less than minimum length (%d) to include the COM descriptor directory", ddLength, pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
	}

	dir, err := readMetadataDirectory(pefile, pe64)
	if err != nil {
		return nil, err
	}
	version, rawHeaps, err := readMetadata(pefile, dir.VirtualAddress)
	if err != nil {
		return nil, err
	}
	f := &Metadata{
		Version: version,
	}
	var tableHeap *heap
	for _, h := range rawHeaps {
		switch h.name {
		case "#Strings":
			f.Strings, err = readStringHeap(h)
		case "#US":
			f.US, err = readUSHeap(h)
		case "#Blob":
			f.Blob, err = readBlobHeap(h)
		case "#GUID":
			f.GUID, err = readGUIDHeap(h)
		case "#~":
			tableHeap = h
		}
		if err != nil {
			return nil, err
		}
	}
	if tableHeap != nil {
		f.Tables, f.layout, err = readTablesHeap(tableHeap, &heaps{f.Strings, f.Blob, f.GUID})
		if err != nil {
			return nil, err
		}
	}
	return f, nil
}

// readMetadataDirectory reads the metadata virtual directory from the CLI header in the pefile.
func readMetadataDirectory(pefile *pe.File, pe64 bool) (pe.DataDirectory, error) {
	// grab the com descriptor data directory entry.
	var comdd pe.DataDirectory
	if pe64 {
		comdd = pefile.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
	} else {
		comdd = pefile.OptionalHeader.(*pe.OptionalHeader32).DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
	}

	// figure out which section contains the COM descriptor directory table
	ds := sectionByRVA(pefile, comdd.VirtualAddress)
	if ds == nil {
		return pe.DataDirectory{}, errors.New("COM descriptor directory table is missing")
	}

	// read COM descriptor directory table might be in a large section,
	// we better don't call ds.Data()
	r := ds.Open()

	// seek to the COM descriptor data directory virtual address.
	_, err := r.Seek(int64(comdd.VirtualAddress-ds.VirtualAddress), io.SeekStart)
	if err != nil {
		return pe.DataDirectory{}, fmt.Errorf("failure to seek to the COM descriptor data directory root: %v", err)
	}

	read := func(data any) bool {
		err = binary.Read(r, binary.LittleEndian, data)
		return err == nil
	}
	readDataDirectory := func(data *pe.DataDirectory) bool {
		return read(&data.VirtualAddress) && read(&data.Size)
	}

	// The CLI header contains all of the runtime-specific data entries and other information.
	// We are only interested on in the metadata data directory.
	// Defined in §II.25.3.3.
	var hdr struct {
		Size                uint32
		MajorRuntimeVersion uint16
		MinorRuntimeVersion uint16
		Metadata            pe.DataDirectory
	}
	if !read(&hdr.Size) ||
		!read(&hdr.MajorRuntimeVersion) ||
		!read(&hdr.MinorRuntimeVersion) ||
		!readDataDirectory(&hdr.Metadata) {
		return pe.DataDirectory{}, fmt.Errorf("failure to read the CLI header: %v", err)
	}
	return hdr.Metadata, nil
}

// readMetadata reads the Metadata from pefile.
func readMetadata(pefile *pe.File, rva uint32) (string, []*heap, error) {
	// figure out which section contains the metadata.
	ds := sectionByRVA(pefile, rva)
	if ds == nil {
		return "", nil, errors.New("metadata section is missing")
	}

	// The metadata section can be huge, we better don't call ds.Data()
	r := ds.Open()

	// seek to the virtual address specified in the COM descriptor data directory.
	rootOffset := int64(rva - ds.VirtualAddress)
	_, err := r.Seek(rootOffset, io.SeekStart)
	if err != nil {
		return "", nil, fmt.Errorf("failure to seek to the metadata root: %v", err)
	}

	read := func(data any) bool {
		err = binary.Read(r, binary.LittleEndian, data)
		return err == nil
	}
	readStr := func(n int, data *string) bool {
		const maxLength = 255
		if n > maxLength {
			err = fmt.Errorf("string length (%d) is higher than the maximum length (%d)", n, maxLength)
			return false
		}
		buf := make([]byte, n)
		err = binary.Read(r, binary.LittleEndian, buf)
		if err == nil {
			i := bytes.IndexByte(buf, 0)
			if i == -1 {
				i = len(buf)
			}
			*data = string(buf[:i])
		}
		return err == nil
	}

	// the Metadata header is defined in §II.24.2.1.
	var hdr struct {
		Signature    uint32
		MajorVersion uint16
		MinorVersion uint16
		Reserved     uint32
		Version      string
		Flags        uint16
	}
	if !read(&hdr.Signature) {
		return "", nil, fmt.Errorf("failure to read the metadata header signature: %v", err)
	}
	// magic signature from II.24.2.1
	const signature = 0x424A5342
	if hdr.Signature != signature {
		return "", nil, fmt.Errorf("metadata header signature (%#X) must be (%#X)", hdr.Signature, signature)
	}
	var streamsCount uint16
	var cstringLength uint32
	if !read(&hdr.MajorVersion) ||
		!read(&hdr.MinorVersion) ||
		!read(&hdr.Reserved) ||
		!read(&cstringLength) ||
		!readStr(int(cstringLength), &hdr.Version) ||
		!read(&hdr.Flags) ||
		!read(&streamsCount) {
		return "", nil, fmt.Errorf("failure to read the metadata header: %v", err)
	}

	readStreamNameStr := func(data *string) bool {
		// the name of the stream as null-terminated variable length array
		// of ASCII characters, padded to the next 4-byte boundary
		// with \x00 characters. The name is limited to 32 characters.
		const nameMaxLength = 32
		const namePadding = 4
		var nameBuf [nameMaxLength]byte
		// Read in chunks of 4 bytes, accumulating the string
		// into nameBuf until the first \x00 character is found.
		var found bool
		for j := 0; j < nameMaxLength; j += namePadding {
			if !read(nameBuf[j : j+namePadding]) {
				break
			}
			idx := bytes.IndexByte(nameBuf[j:j+namePadding], 0)
			if idx != -1 {
				found = true
				*data = string(nameBuf[:idx+j])
				break
			}
		}
		if !found {
			err = errors.New("name not found")
		}
		return err == nil
	}

	// parse stream headers.
	// common case is to have just 5.
	streams := make([]*heap, 0, 5)
	streamNames := make(map[string]struct{}, 5)
	for i := range int(streamsCount) {
		// the stream header is defined in §II.24.2.2.
		var s struct {
			Offset uint32
			Size   uint32
			Name   string
		}
		if !read(&s.Offset) ||
			!read(&s.Size) ||
			!readStreamNameStr(&s.Name) {
			return "", nil, fmt.Errorf("failure to read the stream header (%d): %v", i, err)
		}
		// check for duplicated names.
		if _, ok := streamNames[s.Name]; ok {
			return "", nil, fmt.Errorf("duplicated %s stream", s.Name)
		}
		streamNames[s.Name] = struct{}{}
		sr := io.NewSectionReader(ds, rootOffset+int64(s.Offset), int64(s.Size))
		streams = append(streams, &heap{
			sr:       sr,
			ReaderAt: sr,
			name:     s.Name,
			Size:     s.Size,
		})
	}
	return hdr.Version, streams, nil
}

// sectionByRVA returns the section which contains rva.
func sectionByRVA(pefile *pe.File, rva uint32) *pe.Section {
	for _, s := range pefile.Sections {
		start := s.VirtualAddress
		end := start + s.VirtualSize
		if end < start {
			// s.VirtualAddress + s.VirtualSize overflows.
			continue
		}
		if start <= rva && rva < end {
			return s
		}
	}
	return nil
}

func readGUIDHeap(r *heap) (GUIDHeap, error) {
	buf, err := r.Data()
	if err != nil {
		return nil, fmt.Errorf("fail to read GUID heap: %v", err)
	}
	return GUIDHeap(buf), nil
}

func readUSHeap(r *heap) (USHeap, error) {
	buf, err := r.Data()
	if err != nil {
		return nil, fmt.Errorf("fail to read US heap: %v", err)
	}
	return USHeap(buf), nil
}

func readBlobHeap(r *heap) (BlobHeap, error) {
	buf, err := r.Data()
	if err != nil {
		return nil, fmt.Errorf("fail to read blob heap: %v", err)
	}
	return BlobHeap(buf), nil
}

func readStringHeap(r *heap) (StringHeap, error) {
	buf, err := r.Data()
	if err != nil {
		return nil, fmt.Errorf("fail to read string heap: %v", err)
	}
	if buf[len(buf)-1] != 0 {
		return nil, errors.New("string heap must be null-terminated")
	}
	return StringHeap(buf), nil
}

func readTablesHeap(tableHeap *heap, hps *heaps) (*Tables, *layout, error) {
	// The #~ stream can be huge, we better don't call ds.Data()
	r := tableHeap.Open()

	var err error
	read := func(data any) bool {
		err = binary.Read(r, binary.LittleEndian, data)
		return err == nil
	}

	// parse #~ stream top-level structure, §II.24.2.6.
	var (
		padding6  [6]byte
		heapSizes uint8
		padding1  byte
		valid     uint64
		sorted    uint64
	)
	if !read(&padding6) || !read(&heapSizes) || !read(&padding1) || !read(&valid) || !read(&sorted) {
		return nil, nil, fmt.Errorf("fail to read the tables stream header: %v", err)
	}
	tablesCount := bits.OnesCount64(valid)
	if tablesCount >= int(tableMax) {
		return nil, nil, fmt.Errorf("invalid bit vector of present tables: 0b%b", tablesCount)
	}
	// read an array of tablesCount 4-byte unsigned integers indicating the number of
	// rows for each present table.
	rows := make([]uint32, tablesCount)
	if !read(rows) {
		return nil, nil, fmt.Errorf("fail to read tables stream rows: %v", err)
	}
	var tableRowCounts [tableMax]uint32
	for j, i := 0, 0; i < len(tableRowCounts); i++ {
		if (valid >> i & 1) == 0 {
			continue
		}
		tableRowCounts[i] = rows[j]
		j++
	}
	buf, err := readData(tableHeap.Open(), uint64(tableHeap.Size))
	if err != nil {
		return nil, nil, fmt.Errorf("fail to read tables stream: %v", err)
	}
	layout := generateLayout(heapSizes, tableRowCounts)
	tables := newTables(buf[24+4*tablesCount:], hps, layout)
	return tables, layout, nil
}
