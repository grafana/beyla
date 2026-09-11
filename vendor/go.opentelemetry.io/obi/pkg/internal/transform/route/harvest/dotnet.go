// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"context"
	"debug/pe"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/microsoft/go-winmd/winmd"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/dotnettools"
	"go.opentelemetry.io/obi/pkg/internal/langtools"
)

const (
	maxDotnetAssemblyBytes int64 = 256 * 1024 * 1024
	maxDotnetRoutes              = 10_000
)

type dotnetExtractor struct {
	ctx context.Context
	pe  *pe.File
	md  *winmd.Metadata
	rs  map[string]struct{}
}

func ExtractDotnetRoutes(ctx context.Context, fi *exec.FileInfo) (*RouteHarvesterResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fi == nil {
		return nil, errors.New(".NET route harvesting requires process file info")
	}

	path, err := dotnettools.EntryAssemblyForPID(fi)
	if err != nil {
		return nil, err
	}
	f, found := langtools.OpenMetadataFile(path, maxDotnetAssemblyBytes)
	if f == nil {
		if !found {
			return nil, fmt.Errorf(".NET entry assembly disappeared for pid %d", fi.Pid())
		}
		return nil, fmt.Errorf(".NET entry assembly cannot be scanned for pid %d", fi.Pid())
	}
	defer f.Close()

	p, err := pe.NewFile(f)
	if err != nil {
		return nil, fmt.Errorf("read .NET entry assembly: %w", err)
	}
	defer p.Close()

	// Call the IL and Metadata parser from Microsoft
	m, err := winmd.New(p)
	if err != nil {
		return nil, fmt.Errorf("read .NET metadata: %w", err)
	}
	if m.Tables == nil {
		return nil, errors.New(".NET entry assembly has no metadata tables")
	}

	e := dotnetExtractor{ctx: ctx, pe: p, md: m, rs: map[string]struct{}{}}
	if err := e.attrs(); err != nil {
		return nil, err
	}
	if err := e.il(); err != nil {
		return nil, err
	}

	rs := make([]string, 0, len(e.rs))
	for r := range e.rs {
		rs = append(rs, r)
	}
	sort.Slice(rs, func(i, j int) bool {
		if len(rs[i]) == len(rs[j]) {
			return rs[i] < rs[j]
		}
		return len(rs[i]) > len(rs[j])
	})

	return &RouteHarvesterResult{Routes: rs, Kind: PartialRoutes}, nil
}

func (e *dotnetExtractor) add(raw string) {
	if len(e.rs) >= maxDotnetRoutes {
		return
	}
	if r, ok := dotnetRoute(raw); ok {
		e.rs[r] = struct{}{}
	}
}

// Normalises the dotnet routes, they have bizarre formats like ~/api, or can
// start without a /, like api/customers. For example:
// [Route("api/[controller]")]
// public class ProductsController : ControllerBase
//
//	{
//	    [HttpGet("~/health")]
//	    public IActionResult Health() => Ok();
//	}
func dotnetRoute(raw string) (string, bool) {
	r := strings.TrimSpace(raw)
	if strings.HasPrefix(r, "~/") {
		r = r[1:]
	}
	if r == "" || strings.Contains(r, "://") || strings.ContainsFunc(r, unicode.IsControl) {
		return "", false
	}
	if !strings.HasPrefix(r, "/") {
		r = "/" + r
	}
	if len(r) > 1 {
		r = strings.TrimRight(r, "/")
	}
	return r, r != ""
}

// dotnetLen decodes the ECMA-335 compressed unsigned length prefix used in .NET metadata strings.
func dotnetLen(b []byte) (uint32, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	switch {
	case b[0]&0x80 == 0:
		return uint32(b[0]), 1, true
	case b[0]&0xc0 == 0x80 && len(b) >= 2:
		return uint32(b[0]&0x3f)<<8 | uint32(b[1]), 2, true
	case b[0]&0xe0 == 0xc0 && len(b) >= 4:
		return uint32(b[0]&0x1f)<<24 |
			uint32(b[1])<<16 |
			uint32(b[2])<<8 |
			uint32(b[3]), 4, true
	default:
		return 0, 0, false
	}
}
