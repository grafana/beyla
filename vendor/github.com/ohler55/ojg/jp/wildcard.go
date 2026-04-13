// Copyright (c) 2020, Peter Ohler, All rights reserved.

package jp

import (
	"reflect"
	"sort"
	"strings"

	"github.com/ohler55/ojg/gen"
)

// Wildcard is used as a flag to indicate the path should be displayed in a
// wildcarded representation.
type Wildcard byte

// Append a fragment string representation of the fragment to the buffer
// then returning the expanded buffer.
func (f Wildcard) Append(buf []byte, bracket, first bool) []byte {
	if bracket || f == '#' {
		buf = append(buf, "[*]"...)
	} else {
		if !first {
			buf = append(buf, '.')
		}
		buf = append(buf, '*')
	}
	return buf
}

func (f Wildcard) remove(value any) (out any, changed bool) {
	out = value
	switch tv := value.(type) {
	case []any:
		if 0 < len(tv) {
			changed = true
			out = []any{}
		}
	case map[string]any:
		if 0 < len(tv) {
			changed = true
			for k := range tv {
				delete(tv, k)
			}
		}
	case gen.Array:
		if 0 < len(tv) {
			changed = true
			out = gen.Array{}
		}
	case gen.Object:
		if 0 < len(tv) {
			changed = true
			for k := range tv {
				delete(tv, k)
			}
		}
	case RemovableIndexed:
		size := tv.Size()
		for i := (size - 1); i >= 0; i-- {
			changed = true
			tv.RemoveValueAtIndex(i)
		}
	case Keyed:
		keys := tv.Keys()
		if 0 < len(keys) {
			changed = true
			for _, k := range keys {
				tv.RemoveValueForKey(k)
			}
		}
	default:
		rv := reflect.ValueOf(value)
		switch rv.Kind() {
		case reflect.Slice:
			if 0 < rv.Len() {
				changed = true
				out = reflect.MakeSlice(rv.Type(), 0, 0).Interface()
			}
		case reflect.Map:
			if 0 < rv.Len() {
				changed = true
				out = reflect.MakeMap(rv.Type()).Interface()
			}
		}
	}
	return
}

func (f Wildcard) removeOne(value any) (out any, changed bool) {
	out = value
	switch tv := value.(type) {
	case []any:
		if 0 < len(tv) {
			changed = true
			out = tv[1:]
		}
	case map[string]any:
		if 0 < len(tv) {
			changed = true
			keys := make([]string, 0, len(tv))
			for k := range tv {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			delete(tv, keys[0])
		}
	case gen.Array:
		if 0 < len(tv) {
			changed = true
			out = tv[1:]
		}
	case gen.Object:
		if 0 < len(tv) {
			changed = true
			keys := make([]string, 0, len(tv))
			for k := range tv {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			delete(tv, keys[0])
		}
	case RemovableIndexed:
		if 0 < tv.Size() {
			changed = true
			tv.RemoveValueAtIndex(0)
		}
	case Keyed:
		keys := tv.Keys()
		if 0 < len(keys) {
			changed = true
			sort.Strings(keys)
			tv.RemoveValueForKey(keys[0])
		}
	default:
		rv := reflect.ValueOf(value)
		switch rv.Kind() {
		case reflect.Slice:
			if 0 < rv.Len() {
				changed = true
				out = rv.Slice(1, rv.Len()).Interface()
			}
		case reflect.Map:
			if 0 < rv.Len() {
				changed = true
				keys := rv.MapKeys()
				sort.Slice(keys, func(i, j int) bool {
					return strings.Compare(keys[i].String(), keys[j].String()) < 0
				})
				rv.SetMapIndex(keys[0], reflect.Value{})
			}
		}
	}
	return
}

func (f Wildcard) locate(pp Expr, data any, rest Expr, max int) (locs []Expr) {
	switch td := data.(type) {
	case map[string]any:
		if len(rest) == 0 { // last one
			for k := range td {
				locs = locateAppendFrag(locs, pp, Child(k))
				if 0 < max && max <= len(locs) {
					break
				}
			}
		} else {
			cp := append(pp, nil) // place holder
			for k, v := range td {
				cp[len(pp)] = Child(k)
				locs = locateContinueFrag(locs, cp, v, rest, max)
				if 0 < max && max <= len(locs) {
					break
				}
			}
		}
	case []any:
		if len(rest) == 0 { // last one
			for i := range td {
				locs = locateAppendFrag(locs, pp, Nth(i))
				if 0 < max && max <= len(locs) {
					break
				}
			}
		} else {
			cp := append(pp, nil) // place holder
			for i, v := range td {
				cp[len(pp)] = Nth(i)
				locs = locateContinueFrag(locs, cp, v, rest, max)
				if 0 < max && max <= len(locs) {
					break
				}
			}
		}
	case gen.Object:
		if len(rest) == 0 { // last one
			for k := range td {
				locs = locateAppendFrag(locs, pp, Child(k))
				if 0 < max && max <= len(locs) {
					break
				}
			}
		} else {
			cp := append(pp, nil) // place holder
			for k, v := range td {
				cp[len(pp)] = Child(k)
				locs = locateContinueFrag(locs, cp, v, rest, max)
				if 0 < max && max <= len(locs) {
					break
				}
			}
		}
	case gen.Array:
		if len(rest) == 0 { // last one
			for i := range td {
				locs = locateAppendFrag(locs, pp, Nth(i))
				if 0 < max && max <= len(locs) {
					break
				}
			}
		} else {
			cp := append(pp, nil) // place holder
			for i, v := range td {
				cp[len(pp)] = Nth(i)
				locs = locateContinueFrag(locs, cp, v, rest, max)
				if 0 < max && max <= len(locs) {
					break
				}
			}
		}
	case Keyed:
		keys := td.Keys()
		if len(rest) == 0 { // last one
			for _, k := range keys {
				locs = locateAppendFrag(locs, pp, Child(k))
				if 0 < max && max <= len(locs) {
					break
				}
			}
		} else {
			cp := append(pp, nil) // place holder
			for _, k := range keys {
				v, _ := td.ValueForKey(k)
				cp[len(pp)] = Child(k)
				locs = locateContinueFrag(locs, cp, v, rest, max)
				if 0 < max && max <= len(locs) {
					break
				}
			}
		}
	case Indexed:
		size := td.Size()
		if len(rest) == 0 { // last one
			for i := 0; i < size; i++ {
				locs = locateAppendFrag(locs, pp, Nth(i))
				if 0 < max && max <= len(locs) {
					break
				}
			}
		} else {
			cp := append(pp, nil) // place holder
			for i := 0; i < size; i++ {
				v := td.ValueAtIndex(i)
				cp[len(pp)] = Nth(i)
				locs = locateContinueFrag(locs, cp, v, rest, max)
				if 0 < max && max <= len(locs) {
					break
				}
			}
		}
	case nil:
		// no match
	default:
		rd := reflect.ValueOf(data)
		rt := rd.Type()
		if rt.Kind() == reflect.Ptr {
			rt = rt.Elem()
			rd = rd.Elem()
		}
		if len(rest) == 0 { // last one
			switch rt.Kind() {
			case reflect.Struct:
				for i := rd.NumField() - 1; 0 <= i; i-- {
					rv := rd.Field(i)
					if rv.CanInterface() {
						locs = locateAppendFrag(locs, pp, Child(rt.Field(i).Name))
						if 0 < max && max <= len(locs) {
							break
						}
					}
				}
			case reflect.Slice, reflect.Array:
				for i := 0; i < rd.Len(); i++ {
					rv := rd.Index(i)
					if rv.CanInterface() {
						locs = locateAppendFrag(locs, pp, Nth(i))
						if 0 < max && max <= len(locs) {
							break
						}
					}
				}
			}
		} else {
			cp := append(pp, nil) // place holder
			switch rt.Kind() {
			case reflect.Struct:
				for i := rd.NumField() - 1; 0 <= i; i-- {
					rv := rd.Field(i)
					if rv.CanInterface() {
						cp[len(pp)] = Child(rt.Field(i).Name)
						locs = locateContinueFrag(locs, cp, rv.Interface(), rest, max)
						if 0 < max && max <= len(locs) {
							break
						}
					}
				}
			case reflect.Slice, reflect.Array:
				for i := 0; i < rd.Len(); i++ {
					rv := rd.Index(i)
					if rv.CanInterface() {
						cp[len(pp)] = Nth(i)
						locs = locateContinueFrag(locs, cp, rv.Interface(), rest, max)
						if 0 < max && max <= len(locs) {
							break
						}
					}
				}
			}
		}
	}
	return
}

// Walk follows the all elements in a map or slice like element.
func (f Wildcard) Walk(rest, path Expr, nodes []any, cb func(path Expr, nodes []any)) {
	wildWalk(rest, path, nodes, cb, nil)
}

func wildWalk(rest, path Expr, nodes []any, cb func(path Expr, nodes []any), f Frag) {
	path = append(path, nil)
	data := nodes[len(nodes)-1]
	nodes = append(nodes, nil)
	switch tv := data.(type) {
	case []any:
		for i, v := range tv {
			path[len(path)-1] = Nth(i)
			nodes[len(nodes)-1] = v
			if 0 < len(rest) {
				rest[0].Walk(rest[1:], path, nodes, cb)
			} else {
				cb(path, nodes)
			}
			if f != nil {
				f.Walk(rest, path, nodes, cb)
			}
		}
	case map[string]any:
		if 0 < len(tv) {
			keys := make([]string, 0, len(tv))
			for k := range tv {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := tv[k]
				path[len(path)-1] = Child(k)
				nodes[len(nodes)-1] = v
				if 0 < len(rest) {
					rest[0].Walk(rest[1:], path, nodes, cb)
				} else {
					cb(path, nodes)
				}
				if f != nil {
					f.Walk(rest, path, nodes, cb)
				}
			}
		}
	case gen.Array:
		for i, v := range tv {
			path[len(path)-1] = Nth(i)
			nodes[len(nodes)-1] = v
			if 0 < len(rest) {
				rest[0].Walk(rest[1:], path, nodes, cb)
			} else {
				cb(path, nodes)
			}
			if f != nil {
				f.Walk(rest, path, nodes, cb)
			}
		}
	case gen.Object:
		if 0 < len(tv) {
			keys := make([]string, 0, len(tv))
			for k := range tv {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := tv[k]
				path[len(path)-1] = Child(k)
				nodes[len(nodes)-1] = v
				if 0 < len(rest) {
					rest[0].Walk(rest[1:], path, nodes, cb)
				} else {
					cb(path, nodes)
				}
				if f != nil {
					f.Walk(rest, path, nodes, cb)
				}
			}
		}
	case Indexed:
		for i := 0; i < tv.Size(); i++ {
			path[len(path)-1] = Nth(i)
			nodes[len(nodes)-1] = tv.ValueAtIndex(i)
			if 0 < len(rest) {
				rest[0].Walk(rest[1:], path, nodes, cb)
			} else {
				cb(path, nodes)
			}
			if f != nil {
				f.Walk(rest, path, nodes, cb)
			}
		}
	case Keyed:
		keys := tv.Keys()
		sort.Strings(keys)
		for _, k := range keys {
			path[len(path)-1] = Child(k)
			nodes[len(nodes)-1], _ = tv.ValueForKey(k)
			if 0 < len(rest) {
				rest[0].Walk(rest[1:], path, nodes, cb)
			} else {
				cb(path, nodes)
			}
			if f != nil {
				f.Walk(rest, path, nodes, cb)
			}
		}
	case nil, bool, string, float64, float32, gen.Bool, gen.Float, gen.String,
		int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64, gen.Int:
		// A bypass to avoid using reflection in the default case.
	default:
		if rt := reflect.TypeOf(tv); rt != nil {
			rd := reflect.ValueOf(tv)
		rwalk:
			switch rt.Kind() {
			case reflect.Ptr:
				rt = rt.Elem()
				rd = rd.Elem()
				goto rwalk
			case reflect.Struct:
				cnt := rd.NumField()
				for i := 0; i < cnt; i++ {
					rv := rd.Field(i)
					if rv.CanInterface() {
						path[len(path)-1] = Child(rt.Field(i).Name)
						nodes[len(nodes)-1] = rv.Interface()
						if 0 < len(rest) {
							rest[0].Walk(rest[1:], path, nodes, cb)
						} else {
							cb(path, nodes)
						}
						if f != nil {
							f.Walk(rest, path, nodes, cb)
						}
					}
				}
			case reflect.Slice, reflect.Array:
				// Iterate in reverse order as that puts values on the stack in reverse.
				for i := 0; i < rd.Len(); i++ {
					rv := rd.Index(i)
					if rv.CanInterface() {
						path[len(path)-1] = Nth(i)
						nodes[len(nodes)-1] = rv.Interface()
						if 0 < len(rest) {
							rest[0].Walk(rest[1:], path, nodes, cb)
						} else {
							cb(path, nodes)
						}
						if f != nil {
							f.Walk(rest, path, nodes, cb)
						}
					}
				}
			case reflect.Map:
				keys := rd.MapKeys()
				sort.Slice(keys, func(i, j int) bool {
					return keys[i].String() < keys[j].String()
				})
				for _, kv := range keys {
					rv := rd.MapIndex(kv)
					if rv.CanInterface() {
						path[len(path)-1] = Child(kv.String())
						nodes[len(nodes)-1] = rv.Interface()
						if 0 < len(rest) {
							rest[0].Walk(rest[1:], path, nodes, cb)
						} else {
							cb(path, nodes)
						}
						if f != nil {
							f.Walk(rest, path, nodes, cb)
						}
					}
				}
			}
		}
	}
}
