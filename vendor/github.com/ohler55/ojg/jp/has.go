// Copyright (c) 2020, Peter Ohler, All rights reserved.

package jp

import (
	"reflect"

	"github.com/ohler55/ojg/gen"
)

// Has returns true if there is a value ot the end of the path specified. A
// nil value is still a value.
func (x Expr) Has(data any) bool {
	if len(x) == 0 {
		return false
	}
	var v any
	var prev any
	var has bool

	stack := make([]any, 0, 64)
	defer func() {
		stack = stack[0:cap(stack)]
		for i := len(stack) - 1; 0 <= i; i-- {
			stack[i] = nil
		}
	}()
	stack = append(stack, data)
	f := x[0]
	fi := fragIndex(0) // frag index
	stack = append(stack, fi)

	for 1 < len(stack) { // must have at least a data element and a fragment index
		prev = stack[len(stack)-2]
		if ii, up := prev.(fragIndex); up {
			stack = stack[:len(stack)-1]
			fi = ii & fragIndexMask
			f = x[fi]
			continue
		}
		stack[len(stack)-2] = stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		has = false
		switch tf := f.(type) {
		case Child:
			switch tv := prev.(type) {
			case map[string]any:
				v, has = tv[string(tf)]
			case Keyed:
				v, has = tv.ValueForKey(string(tf))
			case gen.Object:
				v, has = tv[string(tf)]
			default:
				if !isNil(tv) {
					v, has = reflectGetChild(tv, string(tf))
				}
			}
			if has {
				if int(fi) == len(x)-1 { // last one
					return true
				}
				switch v.(type) {
				case nil, bool, string, float64, float32,
					int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64,
					gen.Bool, gen.Int, gen.Float, gen.String:
				case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
					stack = append(stack, v)
				default:
					if rt := reflect.TypeOf(v); rt != nil {
						switch rt.Kind() {
						case reflect.Pointer, reflect.Slice, reflect.Struct, reflect.Array:
							stack = append(stack, v)
						}
					}
				}
			}
		case Nth:
			i := int(tf)
			switch tv := prev.(type) {
			case []any:
				if i < 0 {
					i = len(tv) + i
				}
				if 0 <= i && i < len(tv) {
					v = tv[i]
					has = true
				}
			case Indexed:
				if i < 0 {
					i = tv.Size() + i
				}
				if 0 <= i && i < tv.Size() {
					v = tv.ValueAtIndex(i)
					has = true
				}
			case gen.Array:
				if i < 0 {
					i = len(tv) + i
				}
				if 0 <= i && i < len(tv) {
					v = tv[i]
					has = true
				}
			default:
				if !isNil(tv) {
					v, has = reflectGetNth(tv, i)
				}
			}
			if has {
				if int(fi) == len(x)-1 { // last one
					return true
				}
				switch v.(type) {
				case nil, bool, string, float64, float32, gen.Bool, gen.Float, gen.String,
					int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64, gen.Int:
				case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
					stack = append(stack, v)
				default:
					if rt := reflect.TypeOf(v); rt != nil {
						switch rt.Kind() {
						case reflect.Pointer, reflect.Slice, reflect.Struct, reflect.Array:
							stack = append(stack, v)
						}
					}
				}
			}
		case Wildcard:
			switch tv := prev.(type) {
			case map[string]any:
				if int(fi) == len(x)-1 { // last one
					if 0 < len(tv) {
						return true
					}
				} else {
					for _, v = range tv {
						switch v.(type) {
						case nil, bool, string, float64, float32,
							int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64,
							gen.Bool, gen.Int, gen.Float, gen.String:
						case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
							stack = append(stack, v)
						default:
							if rt := reflect.TypeOf(v); rt != nil {
								switch rt.Kind() {
								case reflect.Pointer, reflect.Slice, reflect.Struct, reflect.Array:
									stack = append(stack, v)
								}
							}
						}
					}
				}
			case []any:
				if int(fi) == len(x)-1 { // last one
					if 0 < len(tv) {
						return true
					}
				} else {
					for i := len(tv) - 1; 0 <= i; i-- {
						v = tv[i]
						switch v.(type) {
						case nil, bool, string, float64, float32,
							int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64,
							gen.Bool, gen.Int, gen.Float, gen.String:
						case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
							stack = append(stack, v)
						default:
							if rt := reflect.TypeOf(v); rt != nil {
								switch rt.Kind() {
								case reflect.Pointer, reflect.Slice, reflect.Struct, reflect.Array:
									stack = append(stack, v)
								}
							}
						}
					}
				}
			case Keyed:
				keys := tv.Keys()
				if int(fi) == len(x)-1 { // last one
					if 0 < len(keys) {
						return true
					}
				} else {
					for _, k := range keys {
						v, _ := tv.ValueForKey(k)
						switch v.(type) {
						case nil, bool, string, float64, float32,
							int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64,
							gen.Bool, gen.Int, gen.Float, gen.String:
						case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
							stack = append(stack, v)
						default:
							if rt := reflect.TypeOf(v); rt != nil {
								switch rt.Kind() {
								case reflect.Pointer, reflect.Slice, reflect.Struct, reflect.Array:
									stack = append(stack, v)
								}
							}
						}
					}
				}
			case Indexed:
				size := tv.Size()
				if int(fi) == len(x)-1 { // last one
					if 0 < size {
						return true
					}
				} else {
					for i := size - 1; 0 <= i; i-- {
						v = tv.ValueAtIndex(i)
						switch v.(type) {
						case nil, bool, string, float64, float32,
							int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64,
							gen.Bool, gen.Int, gen.Float, gen.String:
						case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
							stack = append(stack, v)
						default:
							if rt := reflect.TypeOf(v); rt != nil {
								switch rt.Kind() {
								case reflect.Pointer, reflect.Slice, reflect.Struct, reflect.Array:
									stack = append(stack, v)
								}
							}
						}
					}
				}
			case gen.Object:
				if int(fi) == len(x)-1 { // last one
					if 0 < len(tv) {
						return true
					}
				} else {
					for _, v = range tv {
						switch v.(type) {
						case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
							stack = append(stack, v)
						}
					}
				}
			case gen.Array:
				if int(fi) == len(x)-1 { // last one
					if 0 < len(tv) {
						return true
					}
				} else {
					for i := len(tv) - 1; 0 <= i; i-- {
						v = tv[i]
						switch v.(type) {
						case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
							stack = append(stack, v)
						}
					}
				}
			default:
				if v, has = reflectGetWildOne(tv); has {
					if int(fi) == len(x)-1 { // last one
						return true
					}
					switch v.(type) {
					case nil, bool, string, float64, float32,
						int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64,
						gen.Bool, gen.Int, gen.Float, gen.String:
					case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
						stack = append(stack, v)
					default:
						if rt := reflect.TypeOf(v); rt != nil {
							switch rt.Kind() {
							case reflect.Pointer, reflect.Slice, reflect.Struct, reflect.Array:
								stack = append(stack, v)
							}
						}
					}
				}
			}
		case Descent:
			di, _ := stack[len(stack)-1].(fragIndex)
			// first pass expands, second continues evaluation
			if (di & descentFlag) == 0 {
				switch tv := prev.(type) {
				case map[string]any:
					// Put prev back and slide fi.
					stack[len(stack)-1] = prev
					stack = append(stack, di|descentFlag)
					if int(fi) == len(x)-1 { // last one
						if 0 < len(tv) {
							return true
						}
					}
					for _, v = range tv {
						switch v.(type) {
						case nil, bool, string, float64, float32,
							int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64,
							gen.Bool, gen.Int, gen.Float, gen.String:
						case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
							stack = append(stack, v)
							stack = append(stack, fi|descentChildFlag)
						default:
							if rt := reflect.TypeOf(v); rt != nil {
								switch rt.Kind() {
								case reflect.Pointer, reflect.Slice, reflect.Struct, reflect.Array:
									stack = append(stack, v)
								}
							}
						}
					}
				case []any:
					// Put prev back and slide fi.
					stack[len(stack)-1] = prev
					stack = append(stack, di|descentFlag)
					if int(fi) == len(x)-1 { // last one
						if 0 < len(tv) {
							return true
						}
					}
					for i := len(tv) - 1; 0 <= i; i-- {
						v = tv[i]
						switch v.(type) {
						case nil, bool, string, float64, float32,
							int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64,
							gen.Bool, gen.Int, gen.Float, gen.String:
						case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
							stack = append(stack, v)
							stack = append(stack, fi|descentChildFlag)
						default:
							if rt := reflect.TypeOf(v); rt != nil {
								switch rt.Kind() {
								case reflect.Pointer, reflect.Slice, reflect.Struct, reflect.Array:
									stack = append(stack, v)
								}
							}
						}
					}
				case Keyed:
					keys := tv.Keys()
					// Put prev back and slide fi.
					stack[len(stack)-1] = prev
					stack = append(stack, di|descentFlag)
					if int(fi) == len(x)-1 { // last one
						if 0 < len(keys) {
							return true
						}
					}
					for _, k := range keys {
						v, _ = tv.ValueForKey(k)
						switch v.(type) {
						case nil, bool, string, float64, float32,
							int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64,
							gen.Bool, gen.Int, gen.Float, gen.String:
						case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
							stack = append(stack, v)
							stack = append(stack, fi|descentChildFlag)
						default:
							if rt := reflect.TypeOf(v); rt != nil {
								switch rt.Kind() {
								case reflect.Pointer, reflect.Slice, reflect.Struct, reflect.Array:
									stack = append(stack, v)
								}
							}
						}
					}
				case Indexed:
					size := tv.Size()
					// Put prev back and slide fi.
					stack[len(stack)-1] = prev
					stack = append(stack, di|descentFlag)
					if int(fi) == len(x)-1 { // last one
						if 0 < size {
							return true
						}
					}
					for i := size - 1; 0 <= i; i-- {
						v = tv.ValueAtIndex(i)
						switch v.(type) {
						case nil, bool, string, float64, float32,
							int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64,
							gen.Bool, gen.Int, gen.Float, gen.String:
						case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
							stack = append(stack, v)
							stack = append(stack, fi|descentChildFlag)
						default:
							if rt := reflect.TypeOf(v); rt != nil {
								switch rt.Kind() {
								case reflect.Pointer, reflect.Slice, reflect.Struct, reflect.Array:
									stack = append(stack, v)
								}
							}
						}
					}
				case gen.Object:
					// Put prev back and slide fi.
					stack[len(stack)-1] = prev
					stack = append(stack, di|descentFlag)
					if int(fi) == len(x)-1 { // last one
						if 0 < len(tv) {
							return true
						}
					}
					for _, v = range tv {
						switch v.(type) {
						case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
							stack = append(stack, v)
							stack = append(stack, fi|descentChildFlag)
						}
					}
				case gen.Array:
					// Put prev back and slide fi.
					stack[len(stack)-1] = prev
					stack = append(stack, di|descentFlag)
					if int(fi) == len(x)-1 { // last one
						if 0 < len(tv) {
							return true
						}
					}
					for i := len(tv) - 1; 0 <= i; i-- {
						v = tv[i]
						switch v.(type) {
						case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
							stack = append(stack, v)
							stack = append(stack, fi|descentChildFlag)
						}
					}
				}
			} else {
				stack = append(stack, prev)
			}
		case Root:
			if int(fi) == len(x)-1 { // last one
				return true
			}
			stack = append(stack, data)
		case At, Bracket:
			if int(fi) == len(x)-1 { // last one
				return true
			}
			stack = append(stack, prev)
		case Union:
			if int(fi) == len(x)-1 { // last one
				for _, u := range tf {
					has = false
					switch tu := u.(type) {
					case string:
						switch tv := prev.(type) {
						case map[string]any:
							v, has = tv[tu]
						case Keyed:
							v, has = tv.ValueForKey(tu)
						case gen.Object:
							v, has = tv[tu]
						default:
							v, has = reflectGetChild(tv, tu)
						}
					case int64:
						i := int(tu)
						switch tv := prev.(type) {
						case []any:
							if i < 0 {
								i = len(tv) + i
							}
							if 0 <= i && i < len(tv) {
								v = tv[i]
								has = true
							}
						case Indexed:
							if i < 0 {
								i = tv.Size() + i
							}
							if 0 <= i && i < tv.Size() {
								v = tv.ValueAtIndex(i)
								has = true
							}
						case gen.Array:
							if i < 0 {
								i = len(tv) + i
							}
							if 0 <= i && i < len(tv) {
								v = tv[i]
								has = true
							}
						default:
							v, has = reflectGetNth(tv, i)
						}
					}
					if has {
						return true
					}
				}
			} else {
				for ui := len(tf) - 1; 0 <= ui; ui-- {
					u := tf[ui]
					has = false
					switch tu := u.(type) {
					case string:
						switch tv := prev.(type) {
						case map[string]any:
							v, has = tv[tu]
						case Keyed:
							v, has = tv.ValueForKey(tu)
						case gen.Object:
							v, has = tv[tu]
						default:
							v, has = reflectGetChild(tv, tu)
						}
					case int64:
						i := int(tu)
						switch tv := prev.(type) {
						case []any:
							if i < 0 {
								i = len(tv) + i
							}
							if 0 <= i && i < len(tv) {
								v = tv[i]
								has = true
							}
						case Indexed:
							if i < 0 {
								i = tv.Size() + i
							}
							if 0 <= i && i < tv.Size() {
								v = tv.ValueAtIndex(i)
								has = true
							}
						case gen.Array:
							if i < 0 {
								i = len(tv) + i
							}
							if 0 <= i && i < len(tv) {
								v = tv[i]
								has = true
							}
						default:
							v, has = reflectGetNth(tv, i)
						}
					}
					if has {
						switch v.(type) {
						case nil, bool, string, float64, float32, gen.Bool, gen.Float, gen.String,
							int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64, gen.Int:
						case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
							stack = append(stack, v)
						default:
							if rt := reflect.TypeOf(v); rt != nil {
								switch rt.Kind() {
								case reflect.Pointer, reflect.Slice, reflect.Struct, reflect.Array:
									stack = append(stack, v)
								}
							}
						}
					}
				}
			}
		case Slice:
			switch tv := prev.(type) {
			case []any:
				start, end, step := tf.startEndStep(len(tv))
				if step == 0 {
					continue
				}
				if 0 < step {
					if int(fi) == len(x)-1 && start <= end { // last one
						return true
					}
					for i := end; start <= i; i -= step {
						v = tv[i]
						switch v.(type) {
						case nil, bool, string, float64, float32, gen.Bool, gen.Float, gen.String,
							int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64, gen.Int:
						case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
							stack = append(stack, v)
						default:
							if rt := reflect.TypeOf(v); rt != nil {
								switch rt.Kind() {
								case reflect.Pointer, reflect.Slice, reflect.Struct, reflect.Array:
									stack = append(stack, v)
								}
							}
						}
					}
				} else {
					if int(fi) == len(x)-1 && end <= start { // last one
						return true
					}
					for i := end; i <= start; i -= step {
						v = tv[i]
						switch v.(type) {
						case nil, bool, string, float64, float32, gen.Bool, gen.Float, gen.String,
							int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64, gen.Int:
						case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
							stack = append(stack, v)
						default:
							if rt := reflect.TypeOf(v); rt != nil {
								switch rt.Kind() {
								case reflect.Pointer, reflect.Slice, reflect.Struct, reflect.Array:
									stack = append(stack, v)
								}
							}
						}
					}
				}
			case Indexed:
				size := tv.Size()
				start, end, step := tf.startEndStep(size)
				if step == 0 {
					continue
				}
				if 0 < step {
					if int(fi) == len(x)-1 && start <= end { // last one
						return true
					}
					for i := end; start <= i; i -= step {
						v = tv.ValueAtIndex(i)
						switch v.(type) {
						case nil, bool, string, float64, float32, gen.Bool, gen.Float, gen.String,
							int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64, gen.Int:
						case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
							stack = append(stack, v)
						default:
							if rt := reflect.TypeOf(v); rt != nil {
								switch rt.Kind() {
								case reflect.Pointer, reflect.Slice, reflect.Struct, reflect.Array:
									stack = append(stack, v)
								}
							}
						}
					}
				} else {
					if int(fi) == len(x)-1 && end <= start { // last one
						return true
					}
					for i := end; i <= start; i -= step {
						v = tv.ValueAtIndex(i)
						switch v.(type) {
						case nil, bool, string, float64, float32, gen.Bool, gen.Float, gen.String,
							int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64, gen.Int:
						case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
							stack = append(stack, v)
						default:
							if rt := reflect.TypeOf(v); rt != nil {
								switch rt.Kind() {
								case reflect.Pointer, reflect.Slice, reflect.Struct, reflect.Array:
									stack = append(stack, v)
								}
							}
						}
					}
				}
			case gen.Array:
				start, end, step := tf.startEndStep(len(tv))
				if step == 0 {
					continue
				}
				if 0 < step {
					if int(fi) == len(x)-1 && start <= end { // last one
						return true
					}
					for i := end; start <= i; i -= step {
						v = tv[i]
						switch v.(type) {
						case gen.Object, gen.Array:
							stack = append(stack, v)
						}
					}
				} else {
					if int(fi) == len(x)-1 && end <= start { // last one
						return true
					}
					for i := end; i <= start; i -= step {
						v = tv[i]
						switch v.(type) {
						case gen.Object, gen.Array:
							stack = append(stack, v)
						}
					}
				}
			default:
				start := tf[0]
				if start == SliceNotSet {
					start = 0
				}
				if v, has = reflectGetNth(tv, start); has {
					if int(fi) == len(x)-1 { // last one
						return true
					}
					switch v.(type) {
					case nil, bool, string, float64, float32, gen.Bool, gen.Float, gen.String,
						int, uint, int8, int16, int32, int64, uint8, uint16, uint32, uint64, gen.Int:
					case map[string]any, []any, gen.Object, gen.Array, Keyed, Indexed:
						stack = append(stack, v)
					default:
						if rt := reflect.TypeOf(v); rt != nil {
							switch rt.Kind() {
							case reflect.Pointer, reflect.Slice, reflect.Struct, reflect.Array:
								stack = append(stack, v)
							}
						}
					}
				}
			}
		case *Filter:
			before := len(stack)
			ns, _ := tf.evalWithRoot(stack, prev, data)
			stack, _ = ns.([]any)
			if int(fi) == len(x)-1 { // last one
				if before < len(stack) {
					stack = stack[:before]
					return true
				}
			}
		}
		if int(fi) < len(x)-1 {
			if _, ok := stack[len(stack)-1].(fragIndex); !ok {
				fi++
				f = x[fi]
				stack = append(stack, fi)
			}
		}
	}
	return false
}
