// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"encoding/binary"
	"strings"

	"github.com/microsoft/go-winmd/winmd"
)

var dotnetRouteAttrs = map[string]struct{}{
	"RouteAttribute":       {},
	"HttpDeleteAttribute":  {},
	"HttpGetAttribute":     {},
	"HttpHeadAttribute":    {},
	"HttpOptionsAttribute": {},
	"HttpPatchAttribute":   {},
	"HttpPostAttribute":    {},
	"HttpPutAttribute":     {},
}

type dotnetOwner struct {
	ctrl   string
	action string
}

// We are trying to harvest routes declared as ASP.NET MVC attributes, for example:
// [Route("api/[controller]")]
// [HttpGet("{id}")]

func (e *dotnetExtractor) attrs() error {
	types, methods, err := e.attrOwners()
	if err != nil {
		return err
	}

	for i := range e.md.Tables.CustomAttribute.Indices() {
		if err := e.ctx.Err(); err != nil {
			return err
		}
		a, err := e.md.Tables.CustomAttribute.At(i)
		if err != nil {
			return err
		}
		e.addAttr(a, types, methods)
	}
	return nil
}

// attrOwners builds the ownership maps:
//   - associates each type with its controller name
//   - associates each method with its controller and action names
//   - names like ProductsController becomes Products. The reason we drop "Controller" from the
//     name is because ASP.NET defines the controller name as the class name, without the "Controller" suffix.
//     For example:
//     [Route("api/[controller]")]
//     public class ProductsController : ControllerBase
//     this is documented here https://learn.microsoft.com/en-us/aspnet/core/tutorials/first-web-api?view=aspnetcore-10.0&tabs=visual-studio#routing-and-url-paths
func (e *dotnetExtractor) attrOwners() (map[winmd.Index]dotnetOwner, map[winmd.Index]dotnetOwner, error) {
	types := map[winmd.Index]dotnetOwner{}
	methods := map[winmd.Index]dotnetOwner{}
	for i := range e.md.Tables.TypeDef.Indices() {
		if err := e.ctx.Err(); err != nil {
			return nil, nil, err
		}
		t, err := e.md.Tables.TypeDef.At(i)
		if err != nil {
			return nil, nil, err
		}
		ctrl := strings.TrimSuffix(t.Name.String(), "Controller")
		types[i] = dotnetOwner{ctrl: ctrl}
		for mi := range t.MethodList.All() {
			if err := e.ctx.Err(); err != nil {
				return nil, nil, err
			}
			m, err := e.md.Tables.MethodDef.At(mi)
			if err != nil {
				return nil, nil, err
			}
			methods[mi] = dotnetOwner{ctrl: ctrl, action: m.Name.String()}
		}
	}
	return types, methods, nil
}

// addAttr validates and processes one route attribute at a time
func (e *dotnetExtractor) addAttr(
	a winmd.CustomAttribute,
	types, methods map[winmd.Index]dotnetOwner,
) {
	name, ns, ok := e.attrType(a)
	if !ok || ns != "Microsoft.AspNetCore.Mvc" {
		return
	}
	if _, ok := dotnetRouteAttrs[name]; !ok {
		return
	}

	r, ok := dotnetAttrString(a.Value)
	if !ok {
		return
	}
	var owner dotnetOwner
	switch a.Parent.Tag {
	case winmd.HasCustomAttribute_TypeDef:
		owner = types[a.Parent.Index]
	case winmd.HasCustomAttribute_MethodDef:
		owner = methods[a.Parent.Index]
	default:
		return
	}
	e.add(dotnetTokens(r, owner))
}

func (e *dotnetExtractor) attrType(a winmd.CustomAttribute) (string, string, bool) {
	if a.Type.Tag != winmd.CustomAttributeType_MemberRef {
		return "", "", false
	}
	m, err := e.md.Tables.MemberRef.At(a.Type.Index)
	if err != nil || m.Name.String() != ".ctor" {
		return "", "", false
	}
	return e.memberType(m)
}

func (e *dotnetExtractor) memberType(m winmd.MemberRef) (string, string, bool) {
	switch m.Class.Tag {
	case winmd.MemberRefParent_TypeRef:
		t, err := e.md.Tables.TypeRef.At(m.Class.Index)
		if err != nil {
			return "", "", false
		}
		return t.Name.String(), t.Namespace.String(), true
	case winmd.MemberRefParent_TypeDef:
		t, err := e.md.Tables.TypeDef.At(m.Class.Index)
		if err != nil {
			return "", "", false
		}
		return t.Name.String(), t.Namespace.String(), true
	default:
		return "", "", false
	}
}

func dotnetAttrString(b []byte) (string, bool) {
	if len(b) < 3 || binary.LittleEndian.Uint16(b) != 1 {
		return "", false
	}
	return dotnetString(b[2:])
}

func dotnetString(b []byte) (string, bool) {
	if len(b) == 0 || b[0] == 0xff {
		return "", false
	}
	n, z, ok := dotnetLen(b)
	if !ok || n == 0 || uint64(z)+uint64(n) > uint64(len(b)) {
		return "", false
	}
	return string(b[z : z+int(n)]), true
}

// dotnetTokens replaces the ASP.NET attribute route tokens with their attribute owner.
// For example:
// [Route("api/[controller]")]
// public class ProductsController : ControllerBase
//
//	{
//	    [HttpGet("[action]/{id}")]
//	    public IActionResult Get(int id) => Ok();
//	}
//
// gets converted to /api/Products/Get/{id}
// controller, action and area are the special keywords .NET uses, we don't handle area
// because it will require tracking additional metadata, like [Area(...)] attributes.
func dotnetTokens(r string, owner dotnetOwner) string {
	var b strings.Builder
	for len(r) > 0 {
		start := strings.IndexByte(r, '[')
		if start < 0 {
			b.WriteString(r)
			break
		}
		b.WriteString(r[:start])
		r = r[start:]
		end := strings.IndexByte(r, ']')
		if end < 0 {
			b.WriteString(r)
			break
		}
		token := r[1:end]
		switch {
		case strings.EqualFold(token, "controller") && owner.ctrl != "":
			b.WriteString(owner.ctrl)
		case strings.EqualFold(token, "action") && owner.action != "":
			b.WriteString(owner.action)
		default:
			b.WriteString(r[:end+1])
		}
		r = r[end+1:]
	}
	return b.String()
}
