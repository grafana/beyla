// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"debug/pe"
	"encoding/binary"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/microsoft/go-winmd/winmd"
)

const (
	maxDotnetMethodBytes = 16 * 1024 * 1024
	methodDef            = uint32(0x06000000)
	memberRef            = uint32(0x0a000000)
	methodSpec           = uint32(0x2b000000)
	userString           = uint32(0x70)
	tokenMask            = uint32(0x00ffffff)
	tokenShift           = 24
	opcodeSize           = 1
	tokenSize            = 4
	call                 = 0x28
	callvirt             = 0x6f
	ldstr                = 0x72
	methodFormatMask     = 0x03
	tinyMethodFormat     = 0x02
	fatMethodFormat      = 0x03
)

type dotnetCall struct {
	mapcontroller bool
}

var dotnetMapMethods = map[string]dotnetCall{
	"Map":                    {},
	"MapAreaControllerRoute": {mapcontroller: true},
	"MapBlazorHub":           {},
	"MapControllerRoute":     {mapcontroller: true},
	"MapDelete":              {},
	"MapFallback":            {},
	"MapGet":                 {},
	"MapGroup":               {},
	"MapHealthChecks":        {},
	"MapHub":                 {},
	"MapMethods":             {},
	"MapPatch":               {},
	"MapPost":                {},
	"MapPut":                 {},
}

func (e *dotnetExtractor) il() error {
	calls, err := e.routeCalls()
	if err != nil {
		return err
	}
	if len(calls) == 0 {
		return nil
	}

	for i := range e.md.Tables.MethodDef.Indices() {
		if err := e.ctx.Err(); err != nil {
			return err
		}
		m, err := e.md.Tables.MethodDef.At(i)
		if err != nil {
			return err
		}
		code, ok := dotnetMethodIL(e.pe, m.RVA)
		if !ok {
			continue
		}
		e.scanIL(code, calls)
	}
	return nil
}

// routeCalls finds:
// - MemberRef tokens (0x0a...) for methods under Microsoft.AspNetCore.Builder
// - MethodSpec tokens (0x2b...) for generic instantiations of those methods
// this is then used in scanIL.
func (e *dotnetExtractor) routeCalls() (map[uint32]dotnetCall, error) {
	calls := map[uint32]dotnetCall{}
	refs := map[winmd.Index]dotnetCall{}
	for i := range e.md.Tables.MemberRef.Indices() {
		if err := e.ctx.Err(); err != nil {
			return nil, err
		}
		m, err := e.md.Tables.MemberRef.At(i)
		if err != nil {
			return nil, err
		}
		call, ok := dotnetMapMethods[m.Name.String()]
		if !ok {
			continue
		}
		_, ns, ok := e.memberType(m)
		if !ok || ns != "Microsoft.AspNetCore.Builder" {
			continue
		}
		refs[i] = call
		calls[memberRef|uint32(i+1)] = call
	}

	for i := range e.md.Tables.MethodSpec.Indices() {
		if err := e.ctx.Err(); err != nil {
			return nil, err
		}
		m, err := e.md.Tables.MethodSpec.At(i)
		if err != nil {
			return nil, err
		}
		if m.Method.Tag != winmd.MethodDefOrRef_MemberRef {
			continue
		}
		if call, ok := refs[m.Method.Index]; ok {
			calls[methodSpec|uint32(i+1)] = call
		}
	}
	return calls, nil
}

// The general idea is to find all ldstr opcodes with "/", but there may
// be way too many. So we try harder, we look for ldstr followed by a call to MapGet
// which is typically what registers the route, for example:
// ldstr "/api/customers"  // load route string
// ...
// call MapGet             // register route
func (e *dotnetExtractor) scanIL(code []byte, calls map[uint32]dotnetCall) {
	var route string
	var template string
	var paths []string
	for i := 0; i+opcodeSize+tokenSize <= len(code); i++ {
		switch code[i] {
		case ldstr:
			token := binary.LittleEndian.Uint32(code[i+opcodeSize:])
			if token>>tokenShift != userString {
				continue
			}
			r, ok := dotnetUserString(e.md.US, token&tokenMask)
			if ok {
				if strings.Contains(r, "{") && strings.Contains(r, "}") {
					template = r
				}
				if strings.Contains(r, "/") {
					paths = append(paths, r)
				}
				if strings.HasPrefix(r, "/") || strings.HasPrefix(r, "~/") {
					route = r
				}
			}
			i += tokenSize
		case call, callvirt:
			token := binary.LittleEndian.Uint32(code[i+opcodeSize:])
			if call, ok := calls[token]; ok {
				if call.mapcontroller {
					if template != "" {
						e.add(template)
					} else if len(paths) > 0 {
						e.add(paths[0])
					}
				} else if route != "" {
					e.add(route)
				}
			}
			if e.validMethodToken(token) {
				route = ""
				template = ""
				paths = nil
				i += tokenSize
			}
		}
	}
}

func (e *dotnetExtractor) validMethodToken(token uint32) bool {
	row := token & tokenMask
	if row == 0 {
		return false
	}
	switch token &^ tokenMask {
	case methodDef:
		return row <= e.md.Tables.MethodDef.Len()
	case memberRef:
		return row <= e.md.Tables.MemberRef.Len()
	case methodSpec:
		return row <= e.md.Tables.MethodSpec.Len()
	default:
		return false
	}
}

// This function pulls the string from the dotnet IL. For example, say ldstr "/api", it will
// be encoded as:
// Offset  Bytes
// 0       00
// 1       09                  compressed payload length
// 2       2f 00               "/"
// 4       61 00               "a"
// 6       70 00               "p"
// 8       69 00               "i"
// 10      00                  metadata terminal byte
//
// Rough outline of the steps:
// - reads the compressed length (e.g 9 from above)
// - ignores the final metadata terminal byte.
// - reads the remaining bytes as utf16 little endian code units
// - finally, decodes and returns "/api"
func dotnetUserString(h winmd.USHeap, off uint32) (string, bool) {
	if off == 0 || uint64(off) >= uint64(len(h)) {
		return "", false
	}
	n, z, ok := dotnetLen(h[off:])
	start := uint64(off) + uint64(z)
	end := start + uint64(n)
	if !ok || n < 1 || end > uint64(len(h)) {
		return "", false
	}
	b := h[start : end-1]
	if len(b)%2 != 0 {
		return "", false
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u)), true
}

// dotnetMethodIL converts the method PE(Portable Executable format) to RVA(Relative Virtual Address).
// It finds the PE section which contains the RVA and then converts it to the file position. We handle
// both CLR IL header formats:
// - tiny, where the code size is encoded as 1 byte
// - fat, where the code and the header size are separate fields
func dotnetMethodIL(p *pe.File, rva uint32) ([]byte, bool) {
	if rva == 0 {
		return nil, false
	}
	for _, s := range p.Sections {
		if rva < s.VirtualAddress || uint64(rva-s.VirtualAddress) >= uint64(s.Size) {
			continue
		}

		r := s.Open()
		if _, err := r.Seek(int64(rva-s.VirtualAddress), io.SeekStart); err != nil {
			return nil, false
		}
		var head [12]byte
		if _, err := io.ReadFull(r, head[:1]); err != nil {
			return nil, false
		}

		var size, skip uint32
		switch head[0] & methodFormatMask {
		case tinyMethodFormat:
			size = uint32(head[0] >> 2)
		case fatMethodFormat:
			if _, err := io.ReadFull(r, head[1:]); err != nil {
				return nil, false
			}
			hdr := uint32(binary.LittleEndian.Uint16(head[:])>>12) * 4
			if hdr < uint32(len(head)) {
				return nil, false
			}
			size = binary.LittleEndian.Uint32(head[4:8])
			skip = hdr - uint32(len(head))
		default:
			return nil, false
		}
		if size > maxDotnetMethodBytes {
			return nil, false
		}
		if skip > 0 {
			if _, err := r.Seek(int64(skip), io.SeekCurrent); err != nil {
				return nil, false
			}
		}

		code := make([]byte, size)
		if _, err := io.ReadFull(r, code); err != nil {
			return nil, false
		}
		return code, true
	}
	return nil, false
}
