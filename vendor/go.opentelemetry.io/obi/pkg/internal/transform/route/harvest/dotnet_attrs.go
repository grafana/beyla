// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package harvest // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"

import (
	"log/slog"
	"strings"

	"github.com/microsoft/go-winmd/winmd"
)

const (
	dotnetMvcNamespace     = "Microsoft.AspNetCore.Mvc"
	dotnetRoutingNamespace = "Microsoft.AspNetCore.Mvc.Routing"
	dotnetHTTPMethodAttr   = "HttpMethodAttribute"
	dotnetAcceptVerbsAttr  = "AcceptVerbsAttribute"
	dotnetRouteProperty    = "Route"
	dotnetTemplateParam    = "template"
	dotnetMaxBaseTypes     = 32
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

// A cancelled context leaves the map partial, attrs() reports the cancellation.
func (e *dotnetExtractor) customCtors() map[winmd.Index]int {
	if e.routeCtors == nil {
		if err := e.customRouteCtors(); err != nil {
			slog.Debug("cannot collect .NET custom route attributes", "error", err)
		}
	}
	return e.routeCtors
}

// customRouteCtors maps the constructors of in-assembly HttpMethodAttribute subclasses, such as
// public class HttpQueryAttribute(string template) : HttpMethodAttribute(["QUERY"], template);
// to the position of their parameter named template. Constructors without one are skipped, since
// there is no way to tell which argument is the route.
func (e *dotnetExtractor) customRouteCtors() error {
	e.routeCtors = map[winmd.Index]int{}
	for i := range e.md.Tables.TypeDef.Indices() {
		if err := e.ctx.Err(); err != nil {
			return err
		}
		t, err := e.md.Tables.TypeDef.At(i)
		if err != nil {
			slog.Debug("cannot read .NET type, skipping", "index", i, "error", err)
			continue
		}
		if !e.isRouteAttr(t) {
			continue
		}
		e.addRouteCtors(t)
	}
	return nil
}

func (e *dotnetExtractor) addRouteCtors(t winmd.TypeDef) {
	for mi := range t.MethodList.All() {
		m, err := e.md.Tables.MethodDef.At(mi)
		if err != nil {
			slog.Debug("cannot read .NET method, skipping", "type", t.Name.String(), "error", err)
			continue
		}
		if m.Name.String() != ".ctor" {
			continue
		}
		pos, ok, err := e.templateParam(m)
		if err != nil {
			slog.Debug("cannot read .NET attribute parameters, skipping", "type", t.Name.String(), "error", err)
			continue
		}
		if !ok {
			slog.Debug("route attribute constructor has no template parameter, skipping", "type", t.Name.String())
			continue
		}
		e.routeCtors[mi] = pos
	}
}

func (e *dotnetExtractor) templateParam(m winmd.MethodDef) (int, bool, error) {
	for pi := range m.ParamList.All() {
		p, err := e.md.Tables.Param.At(pi)
		if err != nil {
			return 0, false, err
		}
		if p.Sequence > 0 && strings.EqualFold(p.Name.String(), dotnetTemplateParam) {
			return int(p.Sequence) - 1, true, nil
		}
	}
	return 0, false, nil
}

func (e *dotnetExtractor) isRouteAttr(t winmd.TypeDef) bool {
	for range dotnetMaxBaseTypes {
		switch t.Extends.Tag {
		case winmd.TypeDefOrRef_TypeRef:
			base, err := e.md.Tables.TypeRef.At(t.Extends.Index)
			if err != nil {
				return false
			}
			return isDotnetRouteBase(base.Name.String(), base.Namespace.String())
		case winmd.TypeDefOrRef_TypeDef:
			base, err := e.md.Tables.TypeDef.At(t.Extends.Index)
			if err != nil {
				return false
			}
			t = base
		case winmd.TypeDefOrRef_TypeSpec:
			slog.Debug("generic .NET base type is not supported, skipping attribute", "type", t.Name.String())
			return false
		default:
			return false
		}
	}
	slog.Debug("too many .NET base types, skipping attribute", "type", t.Name.String())
	return false
}

func isDotnetRouteBase(name, ns string) bool {
	if ns == dotnetRoutingNamespace && name == dotnetHTTPMethodAttr {
		return true
	}
	return isDotnetRouteAttr(name, ns)
}

func isDotnetRouteAttr(name, ns string) bool {
	if ns != dotnetMvcNamespace {
		return false
	}
	_, ok := dotnetRouteAttrs[name]
	return ok
}

// addAttr validates and processes one route attribute at a time
func (e *dotnetExtractor) addAttr(
	a winmd.CustomAttribute,
	types, methods map[winmd.Index]dotnetOwner,
) {
	r, ok := e.attrRoute(a)
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

func (e *dotnetExtractor) attrRoute(a winmd.CustomAttribute) (string, bool) {
	if a.Type.Tag == winmd.CustomAttributeType_MethodDef {
		pos, ok := e.customCtors()[a.Type.Index]
		if !ok {
			return "", false
		}
		return e.argString(a, pos)
	}

	name, ns, ok := e.attrType(a)
	if !ok {
		return "", false
	}
	if ns == dotnetMvcNamespace && name == dotnetAcceptVerbsAttr {
		return e.namedRoute(a)
	}
	if !isDotnetRouteAttr(name, ns) {
		return "", false
	}
	return e.argString(a, 0)
}

func (e *dotnetExtractor) argString(a winmd.CustomAttribute, pos int) (string, bool) {
	v, ok := e.decode(a)
	if !ok || pos >= len(v.FixedArguments) {
		return "", false
	}
	r, ok := v.FixedArguments[pos].Value.(string)
	return r, ok && r != ""
}

// namedRoute reads the Route property, for example: [AcceptVerbs("GET", "POST", Route = "api/items")]
func (e *dotnetExtractor) namedRoute(a winmd.CustomAttribute) (string, bool) {
	v, ok := e.decode(a)
	if !ok {
		return "", false
	}
	for _, n := range v.NamedArguments {
		if n.Name != dotnetRouteProperty {
			continue
		}
		r, ok := n.Value.(string)
		return r, ok && r != ""
	}
	return "", false
}

func (e *dotnetExtractor) decode(a winmd.CustomAttribute) (winmd.CustomAttributeValue, bool) {
	if e.decoder == nil {
		e.decoder = winmd.NewCustomAttributeDecoder(e.md)
	}
	v, err := e.decoder.Decode(a)
	if err != nil {
		slog.Debug("cannot decode .NET route attribute", "error", err)
		return winmd.CustomAttributeValue{}, false
	}
	return v, true
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
