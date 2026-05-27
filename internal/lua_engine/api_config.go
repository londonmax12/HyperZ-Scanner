package lua_engine

import (
	lua "github.com/yuin/gopher-lua"
)

// pushConfig converts the per-check settings bag the operator
// supplied via YAML into a Lua table for `ctx.config`. The map's
// shape comes straight out of yaml.v3's decode-into-any path, so
// values may be:
//
//   - string, bool, int, int64, uint64, float64
//   - []any  (YAML sequences)
//   - map[string]any  (yaml.v3's default for mappings)
//   - nil  (explicit ~ in YAML)
//
// Unsupported types are pushed as lua.LNil rather than raising; a
// future YAML construct that returns an unexpected concrete type
// should not crash a running scan over a value the check probably
// would have ignored anyway. The Lua side authoritatively decides
// which keys it cares about.
//
// nil bag returns an empty table so checks can read `ctx.config.foo`
// without first checking for `nil` ctx.config.
func pushConfig(L *lua.LState, bag map[string]any) *lua.LTable {
	t := L.NewTable()
	if len(bag) == 0 {
		return t
	}
	for k, v := range bag {
		t.RawSetString(k, anyToLValue(L, v))
	}
	return t
}

// anyToLValue maps a YAML-decoded Go value to its Lua equivalent.
// Numeric types are normalized to lua.LNumber (a float64), matching
// how Lua treats numbers natively. Maps become tables; sequences
// become integer-keyed tables starting at index 1 (Lua convention).
func anyToLValue(L *lua.LState, v any) lua.LValue {
	switch x := v.(type) {
	case nil:
		return lua.LNil
	case bool:
		return lua.LBool(x)
	case string:
		return lua.LString(x)
	case int:
		return lua.LNumber(x)
	case int32:
		return lua.LNumber(x)
	case int64:
		return lua.LNumber(x)
	case uint:
		return lua.LNumber(x)
	case uint32:
		return lua.LNumber(x)
	case uint64:
		return lua.LNumber(x)
	case float32:
		return lua.LNumber(x)
	case float64:
		return lua.LNumber(x)
	case []any:
		t := L.NewTable()
		for i, item := range x {
			t.RawSetInt(i+1, anyToLValue(L, item))
		}
		return t
	case map[string]any:
		t := L.NewTable()
		for k, item := range x {
			t.RawSetString(k, anyToLValue(L, item))
		}
		return t
	case map[any]any:
		// yaml.v2 left this shape behind; v3 should not produce it,
		// but the conversion is cheap insurance and lets a future
		// upstream decoder change pass through cleanly.
		t := L.NewTable()
		for k, item := range x {
			ks, ok := k.(string)
			if !ok {
				continue
			}
			t.RawSetString(ks, anyToLValue(L, item))
		}
		return t
	default:
		return lua.LNil
	}
}
