// Copyright (c) 2020, Peter Ohler, All rights reserved.

package jp

import (
	"reflect"
	"strconv"

	"github.com/ohler55/ojg/gen"
)

// SliceNotSet indicates an unset value in a sliace. The standard math package
// fails to compile on 32bit architectures (ARM) with an int overflow. Most
// likley due to math.MaxInt64 being defined as 1<<63 - 1 which default to
// integer values. Since arrays are not likely to be over 2147483647 on a 32
// bit system that is set as the max end specifier for a array range.
const SliceNotSet = 2147483647

// Slice is a slice operation for a JSON path expression.
type Slice [3]int

// NewSlice returns slice with unset element.
func NewSlice() Slice {
	return Slice{SliceNotSet, SliceNotSet, SliceNotSet}
}

// Append a fragment string representation of the fragment to the buffer
// then returning the expanded buffer.
func (f Slice) Append(buf []byte, _, _ bool) []byte {
	buf = append(buf, '[')
	if f[0] != SliceNotSet {
		buf = append(buf, strconv.FormatInt(int64(f[0]), 10)...)
	}
	buf = append(buf, ':')
	if f[1] != SliceNotSet {
		buf = append(buf, strconv.FormatInt(int64(f[1]), 10)...)
	}
	if f[2] != SliceNotSet {
		buf = append(buf, ':')
		buf = append(buf, strconv.FormatInt(int64(f[2]), 10)...)
	}
	buf = append(buf, ']')

	return buf
}

func (f Slice) remove(value any) (out any, changed bool) {
	out = value
	switch tv := value.(type) {
	case []any:
		if start, end, step := f.startEndStep(len(tv)); step != 0 {
			ns := make([]any, 0, len(tv))
			if 0 < step {
				for i, v := range tv {
					if inStep(i, start, end, step) {
						changed = true
					} else {
						ns = append(ns, v)
					}
				}
			} else {
				// Walk in reverse to handle the just-one condition.
				for i := len(tv) - 1; 0 <= i; i-- {
					if inStep(i, start, end, step) {
						changed = true
					} else {
						ns = append(ns, tv[i])
					}
				}
				for i := len(ns)/2 - 1; 0 <= i; i-- {
					ns[i], ns[len(ns)-i-1] = ns[len(ns)-i-1], ns[i]
				}
			}
			if changed {
				out = ns
			}
		}
	case gen.Array:
		if start, end, step := f.startEndStep(len(tv)); step != 0 {
			ns := make(gen.Array, 0, len(tv))
			if 0 < step {
				for i, v := range tv {
					if inStep(i, start, end, step) {
						changed = true
					} else {
						ns = append(ns, v)
					}
				}
			} else {
				for i := len(tv) - 1; 0 <= i; i-- {
					if inStep(i, start, end, step) {
						changed = true
					} else {
						ns = append(ns, tv[i])
					}
				}
				for i := len(ns)/2 - 1; 0 <= i; i-- {
					ns[i], ns[len(ns)-i-1] = ns[len(ns)-i-1], ns[i]
				}
			}
			if changed {
				out = ns
			}
		}
	case RemovableIndexed:
		size := tv.Size()
		if start, end, step := f.startEndStep(size); step != 0 {
			for i := size - 1; 0 <= i; i-- {
				if inStep(i, start, end, step) {
					changed = true
					tv.RemoveValueAtIndex(i)
				}
			}
		}
	default:
		rv := reflect.ValueOf(value)
		if rv.Kind() == reflect.Slice {
			cnt := rv.Len()
			if start, end, step := f.startEndStep(cnt); step != 0 {
				nc := 0
				for i := 0; i < cnt; i++ {
					if inStep(i, start, end, step) {
						changed = true
					} else {
						nc++
					}
				}
				if changed {
					changed = false
					ns := reflect.MakeSlice(rv.Type(), nc, nc)
					if 0 < step {
						ni := 0
						for i := 0; i < cnt; i++ {
							if inStep(i, start, end, step) {
								changed = true
							} else {
								ns.Index(ni).Set(rv.Index(i))
								ni++
							}
						}
					} else {
						ni := nc - 1
						for i := cnt - 1; 0 <= i; i-- {
							if inStep(i, start, end, step) {
								changed = true
							} else {
								ns.Index(ni).Set(rv.Index(i))
								ni--
							}
						}
					}
					out = ns.Interface()
				}
			}
		}
	}
	return
}

func (f Slice) removeOne(value any) (out any, changed bool) {
	out = value
	switch tv := value.(type) {
	case []any:
		if start, end, step := f.startEndStep(len(tv)); step != 0 {
			ns := make([]any, 0, len(tv))
			if 0 < step {
				for i, v := range tv {
					if !changed && inStep(i, start, end, step) {
						changed = true
					} else {
						ns = append(ns, v)
					}
				}
			} else {
				// Walk in reverse to handle the just-one condition.
				for i := len(tv) - 1; 0 <= i; i-- {
					if !changed && inStep(i, start, end, step) {
						changed = true
					} else {
						ns = append(ns, tv[i])
					}
				}
				for i := len(ns)/2 - 1; 0 <= i; i-- {
					ns[i], ns[len(ns)-i-1] = ns[len(ns)-i-1], ns[i]
				}
			}
			if changed {
				out = ns
			}
		}
	case gen.Array:
		if start, end, step := f.startEndStep(len(tv)); step != 0 {
			ns := make(gen.Array, 0, len(tv))
			if 0 < step {
				for i, v := range tv {
					if !changed && inStep(i, start, end, step) {
						changed = true
					} else {
						ns = append(ns, v)
					}
				}
			} else {
				// Walk in reverse to handle the just-one condition.
				for i := len(tv) - 1; 0 <= i; i-- {
					if !changed && inStep(i, start, end, step) {
						changed = true
					} else {
						ns = append(ns, tv[i])
					}
				}
				for i := len(ns)/2 - 1; 0 <= i; i-- {
					ns[i], ns[len(ns)-i-1] = ns[len(ns)-i-1], ns[i]
				}
			}
			if changed {
				out = ns
			}
		}
	case RemovableIndexed:
		size := tv.Size()
		if start, end, step := f.startEndStep(size); step != 0 {
			for i := 0; i < size; i++ {
				if inStep(i, start, end, step) {
					changed = true
					tv.RemoveValueAtIndex(i)
					break
				}
			}
		}
	default:
		rv := reflect.ValueOf(value)
		if rv.Kind() == reflect.Slice {
			cnt := rv.Len()
			if start, end, step := f.startEndStep(cnt); step != 0 {
				nc := 0
				for i := 0; i < cnt; i++ {
					if !changed && inStep(i, start, end, step) {
						changed = true
					} else {
						nc++
					}
				}
				if changed {
					changed = false
					ns := reflect.MakeSlice(rv.Type(), nc, nc)
					if 0 < step {
						ni := 0
						for i := 0; i < cnt; i++ {
							if !changed && inStep(i, start, end, step) {
								changed = true
							} else {
								ns.Index(ni).Set(rv.Index(i))
								ni++
							}
						}
					} else {
						ni := nc - 1
						for i := cnt - 1; 0 <= i; i-- {
							if !changed && inStep(i, start, end, step) {
								changed = true
							} else {
								ns.Index(ni).Set(rv.Index(i))
								ni--
							}
						}
					}
					out = ns.Interface()
				}
			}
		}
	}
	return
}

func inStep(i, start, end, step int) bool {
	if 0 < step {
		return start <= i && i <= end && (i-start)%step == 0
	}
	return end <= i && i <= start && (i-end)%-step == 0
}

func (f Slice) startEndStep(size int) (start, end, step int) {
	// The returns start and end are inclusive, not exclusive.
	start = f[0]
	end = f[1]
	step = f[2]
	if step == SliceNotSet {
		step = 1
	}
	switch {
	case start == SliceNotSet:
		if 0 <= step {
			start = 0
		} else {
			start = size - 1
		}
	case start < 0:
		start = size + start
		if start < 0 {
			start = 0
		}
	case size <= start:
		if 0 <= step {
			// in theory, start = size
			step = 0 // start outside of array; step of 0 indicates not to process
		} else {
			start = size - 1
		}
	}
	switch {
	case end == SliceNotSet:
		if 0 <= step {
			end = size - 1
		} else {
			end = 0
		}
	case end < 0:
		end = size + end
		switch {
		case end < 0:
			if 0 < step {
				step = 0
			} else {
				end = 0
			}
		case 0 < step:
			end--
		default:
			end++
			if size <= end {
				step = 0
			}
		}
	case size <= end:
		end = size - 1
	default:
		if 0 < step {
			end--
		} else {
			end++
			if size <= end {
				step = 0
			}
		}
	}
	if step != 0 {
		end = start + (end-start)/step*step
	}
	return
}

func (f Slice) locate(pp Expr, data any, rest Expr, max int) (locs []Expr) {
	switch td := data.(type) {
	case []any:
		start, end, step := f.startEndStep(len(td))
		if step == 0 {
			return
		}
		if 0 < step {
			if len(rest) == 0 { // last one
				for i := start; i <= end; i += step {
					locs = locateAppendFrag(locs, pp, Nth(i))
				}
			} else {
				cp := append(pp, nil) // place holder
				for i := start; i <= end; i += step {
					cp[len(pp)] = Nth(i)
					locs = locateContinueFrag(locs, cp, td[i], rest, max)
					if 0 < max && max <= len(locs) {
						break
					}
				}
			}
		} else {
			if len(rest) == 0 { // last one
				for i := start; end <= i; i += step {
					locs = locateAppendFrag(locs, pp, Nth(i))
				}
			} else {
				cp := append(pp, nil) // place holder
				for i := start; end <= i; i += step {
					cp[len(pp)] = Nth(i)
					locs = locateContinueFrag(locs, cp, td[i], rest, max)
					if 0 < max && max <= len(locs) {
						break
					}
				}
			}
		}
	case gen.Array:
		start, end, step := f.startEndStep(len(td))
		if step == 0 {
			return
		}
		if 0 < step {
			if len(rest) == 0 { // last one
				for i := start; i <= end; i += step {
					locs = locateAppendFrag(locs, pp, Nth(i))
				}
			} else {
				cp := append(pp, nil) // place holder
				for i := start; i <= end; i += step {
					cp[len(pp)] = Nth(i)
					locs = locateContinueFrag(locs, cp, td[i], rest, max)
					if 0 < max && max <= len(locs) {
						break
					}
				}
			}
		} else {
			if len(rest) == 0 { // last one
				for i := start; end <= i; i += step {
					locs = locateAppendFrag(locs, pp, Nth(i))
				}
			} else {
				cp := append(pp, nil) // place holder
				for i := start; end <= i; i += step {
					cp[len(pp)] = Nth(i)
					locs = locateContinueFrag(locs, cp, td[i], rest, max)
					if 0 < max && max <= len(locs) {
						break
					}
				}
			}
		}
	case Indexed:
		start, end, step := f.startEndStep(td.Size())
		if step == 0 {
			return
		}
		if 0 < step {
			if len(rest) == 0 { // last one
				for i := start; i <= end; i += step {
					locs = locateAppendFrag(locs, pp, Nth(i))
				}
			} else {
				cp := append(pp, nil) // place holder
				for i := start; i <= end; i += step {
					cp[len(pp)] = Nth(i)
					locs = locateContinueFrag(locs, cp, td.ValueAtIndex(i), rest, max)
					if 0 < max && max <= len(locs) {
						break
					}
				}
			}
		} else {
			if len(rest) == 0 { // last one
				for i := start; end <= i; i += step {
					locs = locateAppendFrag(locs, pp, Nth(i))
				}
			} else {
				cp := append(pp, nil) // place holder
				for i := start; end <= i; i += step {
					cp[len(pp)] = Nth(i)
					locs = locateContinueFrag(locs, cp, td.ValueAtIndex(i), rest, max)
					if 0 < max && max <= len(locs) {
						break
					}
				}
			}
		}
	case nil:
		// no match
	default:
		rd := reflect.ValueOf(data)
		rt := rd.Type()
		switch rt.Kind() {
		case reflect.Slice, reflect.Array:
			start, end, step := f.startEndStep(rd.Len())
			if 0 < step {
				if len(rest) == 0 { // last one
					for i := start; i <= end; i += step {
						rv := rd.Index(i)
						if rv.CanInterface() {
							locs = locateAppendFrag(locs, pp, Nth(i))
							if 0 < max && max <= len(locs) {
								break
							}
						}
					}
				} else {
					cp := append(pp, nil) // place holder
					for i := start; i <= end; i += step {
						cp[len(pp)] = Nth(i)
						rv := rd.Index(i)
						if rv.CanInterface() {
							locs = locateContinueFrag(locs, cp, rv.Interface(), rest, max)
							if 0 < max && max <= len(locs) {
								break
							}
						}
					}
				}
			} else {
				if len(rest) == 0 { // last one
					for i := start; end <= i; i += step {
						rv := rd.Index(i)
						if rv.CanInterface() {
							locs = locateAppendFrag(locs, pp, Nth(i))
							if 0 < max && max <= len(locs) {
								break
							}
						}
					}
				} else {
					cp := append(pp, nil) // place holder
					for i := start; end <= i; i += step {
						cp[len(pp)] = Nth(i)
						rv := rd.Index(i)
						if rv.CanInterface() {
							locs = locateContinueFrag(locs, cp, rv.Interface(), rest, max)
							if 0 < max && max <= len(locs) {
								break
							}
						}
					}
				}
			}
		}
	}
	return
}

// Walk each element in a slice as defined by the Slice fragment.
func (f Slice) Walk(rest, path Expr, nodes []any, cb func(path Expr, nodes []any)) {
	var max int
	switch tn := nodes[len(nodes)-1].(type) {
	case []any:
		max = len(tn)
	case gen.Array:
		max = len(tn)
	case Indexed:
		max = tn.Size()
	default:
		rv := reflect.ValueOf(tn)
		if rv.Kind() == reflect.Slice {
			max = rv.Len()
		}
	}
	start, end, step := f.startEndStep(max)
	if step == 0 {
		return
	}
	if 0 < step {
		for i := start; i <= end; i += step {
			Nth(i).Walk(rest, path, nodes, cb)
		}
	} else {
		for i := start; end <= i; i += step {
			Nth(i).Walk(rest, path, nodes, cb)
		}
	}
}
